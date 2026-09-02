import { describe, it } from "vitest";
import { cdp } from "vitest/browser";
import KeygenBrowserWorker from "./keygen.browser.worker.ts?worker";

type KeygenStrategy = "thread_rng" | "system_rng";

type BrowserCdpSession = {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
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

function envValue(name: string): string | undefined {
  const value = import.meta.env?.[name];
  return typeof value === "string" ? value : undefined;
}

function envNumber(name: string, defaultValue: number): number {
  const parsed = Number(envValue(name));
  return Number.isInteger(parsed) && parsed > 0 ? parsed : defaultValue;
}

function envPositiveNumber(name: string): number | undefined {
  const rawValue = envValue(name);
  if (rawValue === undefined) {
    return undefined;
  }

  const parsed = Number(rawValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function envKeygenStrategies(name: string): KeygenStrategy[] {
  const rawValue = envValue(name);
  if (rawValue === undefined) {
    return ["thread_rng", "system_rng"];
  }

  const strategies = rawValue
    .split(",")
    .map((value) => value.trim())
    .filter(isKeygenStrategy);

  return strategies.length > 0 ? strategies : ["thread_rng", "system_rng"];
}

const keygenStrategies = envKeygenStrategies("VITE_RSA_KEYGEN_STRATEGIES");
const concurrentWorkers = envNumber("VITE_RSA_KEYGEN_CONCURRENT_WORKERS", 4);
const repeatCount = envNumber("VITE_RSA_KEYGEN_REPEATS", 5);
const slowKeygenTimeoutMs = envNumber("VITE_RSA_KEYGEN_TIMEOUT_MS", 3_600_000);
const cpuThrottleRate = envPositiveNumber("VITE_RSA_KEYGEN_CPU_THROTTLE_RATE");

function writeTiming(message: string) {
  console.info(message);
}

async function configureCpuThrottling() {
  if (cpuThrottleRate === undefined || cpuThrottleRate === 1) {
    return;
  }

  await (cdp() as BrowserCdpSession).send("Emulation.setCPUThrottlingRate", {
    rate: cpuThrottleRate,
  });
  writeTiming(
    `browser Worker WASM RSA keygen CPU throttling enabled: rate=${cpuThrottleRate}`,
  );
}

function keygenMethodLabel(strategy: KeygenStrategy): string {
  return strategy === "thread_rng"
    ? "IssuerContext.generateWithThreadRng()"
    : "IssuerContext.generateWithSystemRng()";
}

function writeRunTiming(timing: KeygenTiming, runCount: number) {
  writeTiming(
    `${keygenMethodLabel(timing.strategy)} browser Worker WASM RSA keygen repeat ${
      timing.repeat
    }/${repeatCount} worker ${
      timing.run
    }/${runCount} completed in ${(timing.elapsedMs / 1000).toFixed(3)}s`,
  );
}

function writeCanceledRunTiming(
  repeat: number,
  run: number,
  runCount: number,
  strategy: KeygenStrategy,
) {
  writeTiming(
    `${keygenMethodLabel(strategy)} browser Worker WASM RSA keygen repeat ${repeat}/${repeatCount} worker ${run}/${runCount} canceled after first success`,
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
) {
  writeTiming(
    `browser Worker WASM RSA keygen comparison: concurrent_workers=${concurrentWorkers}, repeats=${repeatCount}, samples_per_strategy=${
      repeatCount
    }, strategies=${keygenStrategies.join(
      ",",
    )}, strategy_batches=sequential, finish_condition=first_success, cpu_throttle_rate=${
      cpuThrottleRate ?? 1
    }, wall=${(wallElapsedMs / 1000).toFixed(3)}s`,
  );

  for (const strategy of keygenStrategies) {
    reportKeygenStatsForStrategy(timings, strategy);
    reportKeygenRepeatStats(timings, strategy);
  }

  if (keygenStrategies.length > 1) {
    reportKeygenComparison(timings);
  }
}

function reportKeygenStatsForStrategy(
  timings: readonly KeygenTiming[],
  strategy: KeygenStrategy,
) {
  const strategyTimings = timings.filter(
    (timing) => timing.strategy === strategy,
  );
  const sortedByElapsed = [...strategyTimings].sort(
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
    `${keygenMethodLabel(strategy)} browser Worker WASM RSA keygen summary: runs=${
      strategyTimings.length
    }, fastest=${(fastest.elapsedMs / 1000).toFixed(3)}s (run ${
      fastest.run
    }), slowest=${(slowest.elapsedMs / 1000).toFixed(3)}s (run ${
      slowest.run
    }), average=${average.toFixed(3)}s, median=${median(sortedSeconds).toFixed(
      3,
    )}s`,
  );

  for (const timing of [...strategyTimings].sort(
    (a, b) => a.repeat - b.repeat || a.run - b.run,
  )) {
    writeTiming(
      `${keygenMethodLabel(strategy)} browser Worker WASM RSA keygen sample repeat ${
        timing.repeat
      } worker ${timing.run}: ${(timing.elapsedMs / 1000).toFixed(3)}s`,
    );
  }
}

function reportKeygenRepeatStats(
  timings: readonly KeygenTiming[],
  strategy: KeygenStrategy,
) {
  for (let repeat = 1; repeat <= repeatCount; repeat += 1) {
    const repeatTimings = timings.filter(
      (timing) => timing.strategy === strategy && timing.repeat === repeat,
    );
    const sortedSeconds = repeatTimings
      .map((timing) => timing.elapsedMs / 1000)
      .sort((a, b) => a - b);

    if (sortedSeconds.length === 0) {
      continue;
    }

    writeTiming(
      `${keygenMethodLabel(strategy)} browser Worker WASM RSA keygen repeat ${repeat}/${repeatCount} summary: fastest=${sortedSeconds[0].toFixed(
        3,
      )}s, slowest=${sortedSeconds[sortedSeconds.length - 1].toFixed(
        3,
      )}s, average=${average(sortedSeconds).toFixed(3)}s, median=${median(
        sortedSeconds,
      ).toFixed(3)}s`,
    );
  }
}

function secondsForStrategy(
  timings: readonly KeygenTiming[],
  strategy: KeygenStrategy,
): number[] {
  return timings
    .filter((timing) => timing.strategy === strategy)
    .map((timing) => timing.elapsedMs / 1000)
    .sort((a, b) => a - b);
}

function average(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0) / values.length;
}

function reportKeygenComparison(timings: readonly KeygenTiming[]) {
  const threadSeconds = secondsForStrategy(timings, "thread_rng");
  const systemSeconds = secondsForStrategy(timings, "system_rng");
  const threadMedian = median(threadSeconds);
  const systemMedian = median(systemSeconds);
  const threadAverage = average(threadSeconds);
  const systemAverage = average(systemSeconds);
  const medianWinner: KeygenStrategy =
    threadMedian <= systemMedian ? "thread_rng" : "system_rng";
  const averageWinner: KeygenStrategy =
    threadAverage <= systemAverage ? "thread_rng" : "system_rng";

  writeTiming(
    `browser Worker WASM RSA keygen result: median_winner=${keygenMethodLabel(
      medianWinner,
    )}, thread_median=${threadMedian.toFixed(
      3,
    )}s, system_median=${systemMedian.toFixed(3)}s, average_winner=${keygenMethodLabel(
      averageWinner,
    )}, thread_average=${threadAverage.toFixed(
      3,
    )}s, system_average=${systemAverage.toFixed(3)}s`,
  );
}

function isKeygenStrategy(value: unknown): value is KeygenStrategy {
  return value === "thread_rng" || value === "system_rng";
}

function isKeygenWorkerResponse(value: unknown): value is KeygenWorkerResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as KeygenWorkerResponse;
  return (
    (response.type === "progress" &&
      typeof response.repeat === "number" &&
      typeof response.run === "number" &&
      isKeygenStrategy(response.strategy) &&
      typeof response.message === "string") ||
    (response.type === "timing" &&
      typeof response.timing?.repeat === "number" &&
      typeof response.timing?.run === "number" &&
      isKeygenStrategy(response.timing.strategy) &&
      typeof response.timing.elapsedMs === "number") ||
    (response.type === "error" && typeof response.message === "string")
  );
}

function startBrowserWorkerKeygen(
  repeat: number,
  run: number,
  runCount: number,
  strategy: KeygenStrategy,
): {
  promise: Promise<KeygenTiming>;
  terminate: () => void;
} {
  const worker = new KeygenBrowserWorker();
  let settled = false;

  const promise = new Promise<KeygenTiming>((resolve, reject) => {
    function cleanup() {
      settled = true;
      worker.terminate();
    }

    worker.addEventListener("message", (event: MessageEvent<unknown>) => {
      if (!isKeygenWorkerResponse(event.data)) {
        cleanup();
        reject(
          new Error("RSA keygen browser Worker returned an invalid message"),
        );
        return;
      }

      if (event.data.type === "error") {
        cleanup();
        reject(new Error(event.data.stack ?? event.data.message));
        return;
      }

      if (event.data.type === "progress") {
        writeTiming(
          `${keygenMethodLabel(event.data.strategy)} browser Worker WASM RSA keygen repeat ${
            event.data.repeat
          }/${repeatCount} worker ${
            event.data.run
          }/${runCount}: ${event.data.message}`,
        );
        return;
      }

      writeRunTiming(event.data.timing, runCount);
      cleanup();
      resolve(event.data.timing);
    });

    worker.addEventListener("error", (event) => {
      cleanup();
      reject(
        new Error(
          event.message ||
            "RSA keygen browser Worker failed before returning timing",
        ),
      );
    });

    worker.postMessage({ repeat, repeatCount, run, runCount, strategy });
  });

  return {
    promise,
    terminate: () => {
      if (!settled) {
        settled = true;
        worker.terminate();
        writeCanceledRunTiming(repeat, run, runCount, strategy);
      }
    },
  };
}

async function runBrowserWorkerKeygenRace(
  repeat: number,
  runCount: number,
  strategy: KeygenStrategy,
): Promise<KeygenTiming> {
  const workers = Array.from({ length: runCount }, (_, index) =>
    startBrowserWorkerKeygen(repeat, index + 1, runCount, strategy),
  );

  try {
    return await Promise.race(workers.map((worker) => worker.promise));
  } finally {
    for (const worker of workers) {
      worker.terminate();
    }
  }
}

async function runBrowserWorkerKeygens(
  runCount: number,
): Promise<KeygenTiming[]> {
  const timings: KeygenTiming[] = [];

  for (const strategy of keygenStrategies) {
    for (let repeat = 1; repeat <= repeatCount; repeat += 1) {
      writeTiming(
        `${keygenMethodLabel(strategy)} browser Worker WASM RSA keygen batch starting: repeat=${repeat}/${repeatCount}, workers=${runCount}`,
      );
      timings.push(
        await runBrowserWorkerKeygenRace(repeat, runCount, strategy),
      );
    }
  }

  return timings;
}

describe("RSA issuer key generation in a browser Worker", () => {
  it(
    "generates issuer keys and reports timing",
    async () => {
      await configureCpuThrottling();
      const wallStarted = performance.now();
      const timings = await runBrowserWorkerKeygens(concurrentWorkers);

      reportKeygenStats(timings, performance.now() - wallStarted);
    },
    slowKeygenTimeoutMs,
  );
});
