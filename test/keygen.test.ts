import { describe, expect, it } from "vitest";
import type { JsonValue } from "../pkg/peerbadge_wasm.js";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
  initTracing,
} from "../pkg/peerbadge_wasm.js";

type ProcessLike = {
  env?: Record<string, string | undefined>;
  stdout?: { write: (value: string) => void };
};

type KeygenTiming = {
  readonly run: number;
  readonly elapsedMs: number;
};

type WorkerInstance = {
  on: (event: string, listener: (...args: unknown[]) => void) => void;
};

type WorkerConstructor = new (
  filename: URL,
  options: { readonly type: "module"; readonly execArgv: readonly string[] },
) => WorkerInstance;

type WorkerThreadsModule = {
  readonly Worker: WorkerConstructor;
};

const processLike = (globalThis as { process?: ProcessLike }).process;

function envValue(name: string): string | undefined {
  return processLike?.env?.[name];
}

function envBool(name: string): boolean {
  const value = envValue(name);
  return (
    value === "1" ||
    value === "true" ||
    value === "TRUE" ||
    value === "yes" ||
    value === "YES" ||
    value === "on" ||
    value === "ON"
  );
}

function envNumber(name: string, defaultValue: number): number {
  const parsed = Number(envValue(name));
  return Number.isInteger(parsed) && parsed > 0 ? parsed : defaultValue;
}

const runSlowKeygen = envBool("RUN_RSA_KEYGEN_TESTS");
const keygenRuns = envNumber("RSA_KEYGEN_RUNS", 1);
const runKeygensConcurrently =
  envBool("RSA_KEYGEN_CONCURRENT") && keygenRuns > 1;
const slowKeygenTimeoutMs = envNumber("RSA_KEYGEN_TIMEOUT_MS", 1_200_000);

const credentialInfo = {
  schema: "rsa-keygen-smoke-v1",
  trust_level: 1,
} satisfies JsonValue;

function writeTiming(message: string) {
  if (processLike?.stdout) {
    processLike.stdout.write(`${message}\n`);
  } else {
    console.info(message);
  }
}

function smokeTestGeneratedIssuer(issuer: IssuerContext) {
  const exported = issuer.exportSecretKey();
  expect(exported.issuer_id_secret_key).toMatch(/^[0-9a-f]+$/);
  expect(exported.issuance_secret_key.length).toBeGreaterThan(0);

  const issuerAuthority = issuer.issuerAuthority([]);
  expect(issuerAuthority.issuer.issuer_id_pubkey.length).toBeGreaterThan(0);
  expect(issuerAuthority.issuer.issuance_key.length).toBeGreaterThan(0);

  const holder = HolderContext.generate();
  const result = PendingIssuance.createRequest(
    issuerAuthority,
    credentialInfo,
    holder.publicKey,
  );
  const response = issuer.issueCredential(credentialInfo, result.request);
  const credential = result.pending.finalize(issuerAuthority, response);

  const verifier = new VerificationContext();
  expect(verifier.addIssuerAuthority(issuerAuthority)).toBeUndefined();
  expect(verifier.verifyCredential(credential)).toBe(true);
}

function generateIssuerForTiming(run: number, runCount: number): KeygenTiming {
  const started = Date.now();
  const issuer = IssuerContext.generate();
  const elapsedMs = Date.now() - started;

  writeRunTiming({ run, elapsedMs }, runCount);
  smokeTestGeneratedIssuer(issuer);

  return { run, elapsedMs };
}

function writeRunTiming(timing: KeygenTiming, runCount: number) {
  writeTiming(
    `IssuerContext.generate() wasm RSA keygen run ${timing.run}/${runCount} completed in ${(
      timing.elapsedMs / 1000
    ).toFixed(3)}s`,
  );
}

function median(values: readonly number[]): number {
  const mid = Math.floor(values.length / 2);
  return values.length % 2 === 0
    ? (values[mid - 1] + values[mid]) / 2
    : values[mid];
}

function reportKeygenStats(
  timings: readonly KeygenTiming[],
  wallElapsedMs: number,
  concurrent: boolean,
) {
  const sortedByElapsed = [...timings].sort(
    (a, b) => a.elapsedMs - b.elapsedMs,
  );
  const sortedSeconds = sortedByElapsed.map(
    (timing) => timing.elapsedMs / 1000,
  );
  const average =
    sortedSeconds.reduce((total, value) => total + value, 0) /
    sortedSeconds.length;
  const fastest = sortedByElapsed[0];
  const slowest = sortedByElapsed[sortedByElapsed.length - 1];

  writeTiming(
    `IssuerContext.generate() wasm RSA keygen summary: runs=${timings.length}, concurrent=${concurrent}, wall=${(
      wallElapsedMs / 1000
    ).toFixed(3)}s, fastest=${(fastest.elapsedMs / 1000).toFixed(3)}s (run ${
      fastest.run
    }), slowest=${(slowest.elapsedMs / 1000).toFixed(3)}s (run ${
      slowest.run
    }), average=${average.toFixed(3)}s, median=${median(sortedSeconds).toFixed(
      3,
    )}s`,
  );

  for (const timing of [...timings].sort((a, b) => a.run - b.run)) {
    writeTiming(
      `IssuerContext.generate() wasm RSA keygen sample ${timing.run}: ${(
        timing.elapsedMs / 1000
      ).toFixed(3)}s`,
    );
  }
}

async function importWorkerThreads(): Promise<WorkerThreadsModule> {
  const workerThreadsSpecifier = "node:worker_threads";
  return import(workerThreadsSpecifier) as Promise<WorkerThreadsModule>;
}

function workerSource(run: number, pkgUrl: string): string {
  return `
    import { parentPort } from "node:worker_threads";
    import {
      HolderContext,
      IssuerContext,
      PendingIssuance,
      VerificationContext,
      initTracing,
    } from ${JSON.stringify(pkgUrl)};

    initTracing();

    const credentialInfo = ${JSON.stringify(credentialInfo)};
    const started = Date.now();
    const issuer = IssuerContext.generate();
    const elapsedMs = Date.now() - started;

    const exported = issuer.exportSecretKey();
    if (!/^[0-9a-f]+$/.test(exported.issuer_id_secret_key)) {
      throw new Error("generated issuer identity secret key is not hex");
    }
    if (exported.issuance_secret_key.length === 0) {
      throw new Error("generated issuer issuance secret key is empty");
    }

    const issuerAuthority = issuer.issuerAuthority([]);
    const holder = HolderContext.generate();
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      holder.publicKey,
    );
    const response = issuer.issueCredential(credentialInfo, result.request);
    const credential = result.pending.finalize(issuerAuthority, response);

    const verifier = new VerificationContext();
    verifier.addIssuerAuthority(issuerAuthority);
    if (verifier.verifyCredential(credential) !== true) {
      throw new Error("generated issuer credential verification failed");
    }

    parentPort.postMessage({ run: ${run}, elapsedMs });
  `;
}

function isKeygenTiming(value: unknown): value is KeygenTiming {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as KeygenTiming).run === "number" &&
    typeof (value as KeygenTiming).elapsedMs === "number"
  );
}

function runWorkerKeygen(
  Worker: WorkerConstructor,
  pkgUrl: string,
  run: number,
  runCount: number,
): Promise<KeygenTiming> {
  const worker = new Worker(
    new URL(
      `data:text/javascript,${encodeURIComponent(workerSource(run, pkgUrl))}`,
    ),
    {
      type: "module",
      execArgv: ["--experimental-wasm-modules", "--no-warnings"],
    },
  );

  return new Promise((resolve, reject) => {
    let timing: KeygenTiming | undefined;

    worker.on("message", (message) => {
      if (!isKeygenTiming(message)) {
        reject(new Error("RSA keygen worker returned an invalid message"));
        return;
      }

      timing = message;
      writeRunTiming(timing, runCount);
    });
    worker.on("error", (error) => reject(error));
    worker.on("exit", (code) => {
      if (code === 0 && timing) {
        resolve(timing);
        return;
      }

      reject(new Error(`RSA keygen worker exited with code ${String(code)}`));
    });
  });
}

async function runConcurrentKeygens(runCount: number): Promise<KeygenTiming[]> {
  const { Worker } = await importWorkerThreads();
  const pkgUrl = new URL("../pkg/peerbadge_wasm.js", import.meta.url).href;

  return Promise.all(
    Array.from({ length: runCount }, (_, index) =>
      runWorkerKeygen(Worker, pkgUrl, index + 1, runCount),
    ),
  );
}

async function reportsRsaKeygenTiming() {
  initTracing();

  const wallStarted = Date.now();
  const timings = runKeygensConcurrently
    ? await runConcurrentKeygens(keygenRuns)
    : Array.from({ length: keygenRuns }, (_, index) =>
        generateIssuerForTiming(index + 1, keygenRuns),
      );

  reportKeygenStats(timings, Date.now() - wallStarted, runKeygensConcurrently);
}

describe("RSA issuer key generation", () => {
  if (runSlowKeygen) {
    it(
      "generates issuer keys and reports timing",
      reportsRsaKeygenTiming,
      slowKeygenTimeoutMs,
    );
  } else {
    it.skip(
      "generates issuer keys and reports timing",
      reportsRsaKeygenTiming,
      slowKeygenTimeoutMs,
    );
  }
});
