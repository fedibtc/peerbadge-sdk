import type * as WasmSdkModule from "../pkg/peerbadge_wasm.js";
import type { IssuerContext, JsonValue } from "../pkg/peerbadge_wasm.js";

type WasmSdk = typeof WasmSdkModule;

type KeygenStrategy = "thread_rng" | "system_rng";

type KeygenWorkerRequest = {
  readonly repeat: number;
  readonly repeatCount: number;
  readonly run: number;
  readonly runCount: number;
  readonly strategy: KeygenStrategy;
};

type KeygenTiming = {
  readonly repeat: number;
  readonly run: number;
  readonly strategy: KeygenStrategy;
  readonly elapsedMs: number;
};

type KeygenWorkerResponse =
  | {
      readonly type: "progress";
      readonly repeat: number;
      readonly run: number;
      readonly strategy: KeygenStrategy;
      readonly message: string;
    }
  | {
      readonly type: "timing";
      readonly timing: KeygenTiming;
    }
  | {
      readonly type: "error";
      readonly message: string;
      readonly stack?: string;
    };

type WorkerScope = typeof globalThis & {
  readonly addEventListener: (
    event: "message",
    listener: (event: MessageEvent<KeygenWorkerRequest>) => void,
  ) => void;
  readonly postMessage: (message: KeygenWorkerResponse) => void;
};

const workerScope = globalThis as WorkerScope;
let tracingInitialized = false;
let wasmSdkPromise: Promise<WasmSdk> | undefined;

const credentialInfo = {
  schema: "rsa-keygen-smoke-v1",
  trust_level: 1,
} satisfies JsonValue;

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function loadSdk(): Promise<WasmSdk> {
  wasmSdkPromise ??= import("../pkg/peerbadge_wasm.js");
  return wasmSdkPromise;
}

function smokeTestGeneratedIssuer(sdk: WasmSdk, issuer: IssuerContext) {
  const { HolderContext, PendingIssuance, VerificationContext } = sdk;
  const exported = issuer.exportSecretKey();
  assert(
    /^[0-9a-f]+$/.test(exported.issuer_id_secret_key),
    "generated issuer identity secret key is not hex",
  );
  assert(
    exported.issuance_secret_key.length > 0,
    "generated issuer issuance secret key is empty",
  );

  const issuerAuthority = issuer.issuerAuthority([]);
  assert(
    issuerAuthority.issuer.issuer_id_pubkey.length > 0,
    "generated issuer identity public key is empty",
  );
  assert(
    issuerAuthority.issuer.issuance_key.length > 0,
    "generated issuer issuance public key is empty",
  );

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
  assert(
    verifier.verifyCredential(credential) === true,
    "generated issuer credential verification failed",
  );
}

function keygenStrategyLabel(strategy: KeygenStrategy): string {
  return strategy === "thread_rng" ? "thread RNG" : "system RNG";
}

function generateIssuer(sdk: WasmSdk, strategy: KeygenStrategy): IssuerContext {
  return strategy === "thread_rng"
    ? sdk.IssuerContext.generateWithThreadRng()
    : sdk.IssuerContext.generateWithSystemRng();
}

async function generateIssuerForTiming(
  repeat: number,
  run: number,
  strategy: KeygenStrategy,
): Promise<KeygenTiming> {
  workerScope.postMessage({
    type: "progress",
    repeat,
    run,
    strategy,
    message: "loading WASM SDK",
  });
  const sdk = await loadSdk();

  if (!tracingInitialized) {
    sdk.initTracing();
    tracingInitialized = true;
  }

  const strategyLabel = keygenStrategyLabel(strategy);

  workerScope.postMessage({
    type: "progress",
    repeat,
    run,
    strategy,
    message: `starting RSA keygen with ${strategyLabel}`,
  });
  const started = performance.now();
  const issuer = generateIssuer(sdk, strategy);
  const elapsedMs = performance.now() - started;

  workerScope.postMessage({
    type: "progress",
    repeat,
    run,
    strategy,
    message: `smoke testing generated issuer from ${strategyLabel}`,
  });
  smokeTestGeneratedIssuer(sdk, issuer);

  return { repeat, run, strategy, elapsedMs };
}

workerScope.addEventListener("message", (event) => {
  void (async () => {
    try {
      workerScope.postMessage({
        type: "timing",
        timing: await generateIssuerForTiming(
          event.data.repeat,
          event.data.run,
          event.data.strategy,
        ),
      });
    } catch (error) {
      workerScope.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
    }
  })();
});
