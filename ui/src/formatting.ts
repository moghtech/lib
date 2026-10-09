export function fmtDate(d: Date) {
  const hours = d.getHours();
  const minutes = d.getMinutes();
  return `${fmtMonth(d.getMonth())} ${d.getDate()} ${
    hours > 9 ? hours : "0" + hours
  }:${minutes > 9 ? minutes : "0" + minutes}`;
}

export function fmtMonth(month: number) {
  switch (month) {
    case 0:
      return "Jan";
    case 1:
      return "Feb";
    case 2:
      return "Mar";
    case 3:
      return "Apr";
    case 4:
      return "May";
    case 5:
      return "Jun";
    case 6:
      return "Jul";
    case 7:
      return "Aug";
    case 8:
      return "Sep";
    case 9:
      return "Oct";
    case 10:
      return "Nov";
    case 11:
      return "Dec";
  }
}

export const fmtDateWithMinutes = (d: Date) => {
  // return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  return d.toLocaleString();
};

/**
 * The time from `startTs` to `endTs` (ms timestamps): tenths of a
 * second under a minute ("12.3 seconds"), then minutes and seconds
 * ("1 minute 5 seconds"), then hours and minutes ("2 hours 3
 * minutes"). The duration is rounded once, to the unit shown last,
 * so a part never reads 60 ("1 minute 59.6 seconds" is "2 minutes 0
 * seconds"). An end before the start (clock skew) is no time.
 */
export function fmtDuration(startTs: number, endTs: number) {
  const ms = Math.max(0, endTs - startTs);
  const tenths = Math.round(ms / 100);
  if (tenths < 600) {
    return `${(tenths / 10).toFixed(1)} seconds`;
  }
  const seconds = Math.round(ms / 1_000);
  if (seconds < 3_600) {
    return `${plural(Math.floor(seconds / 60), "minute")} ${plural(seconds % 60, "second")}`;
  }
  const minutes = Math.round(ms / 60_000);
  return `${plural(Math.floor(minutes / 60), "hour")} ${plural(minutes % 60, "minute")}`;
}

/** `count` whole `unit`s: "1 minute", "2 minutes", "0 seconds". */
function plural(count: number, unit: string) {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** Coarse "time until" of a future timestamp: days, falling back to
 * hours / minutes once under a day. */
export function fmtTimeUntil(ms: number) {
  const plural = (count: number, unit: string) =>
    `${count} ${unit}${count === 1 ? "" : "s"}`;
  if (ms >= DAY_MS) return plural(Math.floor(ms / DAY_MS), "day");
  if (ms >= HOUR_MS) return plural(Math.floor(ms / HOUR_MS), "hour");
  if (ms >= MINUTE_MS) return plural(Math.floor(ms / MINUTE_MS), "minute");
  return "< 1 minute";
}

/**
 * UpperCamelCase => Upper Camel Case.
 *
 * Input which isn't made of such words only (eg. "OOMKilled",
 * "exited_1") is returned unchanged, instead of losing the other parts.
 */
export function fmtUpperCamelcase(input: string) {
  const words = /[A-Z][a-z]+|[0-9]+/g;
  if (input.replace(words, "").replace(/[\s_-]/g, "") !== "") {
    return input;
  }
  return input.match(words)?.join(" ") ?? input;
}

/// list_all_items => List All Items
export function fmtSnakeCaseToUpperSpaceCase(snake: string) {
  return (
    snake
      .split("_")
      // Leading / trailing / double underscores leave empty parts.
      .filter((item) => item.length > 0)
      .map((item) => item[0].toUpperCase() + item.slice(1))
      .join(" ")
  );
}

export const BYTES_PER_KB = 1024;
export const BYTES_PER_MB = 1024 * BYTES_PER_KB;
export const BYTES_PER_GB = 1024 * BYTES_PER_MB;

export function fmtSizeBytes(bytes: number) {
  if (bytes >= BYTES_PER_GB) {
    return (bytes / BYTES_PER_GB).toFixed(1) + " GiB";
  } else if (bytes >= BYTES_PER_MB) {
    return (bytes / BYTES_PER_MB).toFixed(1) + " MiB";
  } else if (bytes >= BYTES_PER_KB) {
    return (bytes / BYTES_PER_KB).toFixed(1) + " KiB";
  } else {
    return bytes.toString() + " bytes";
  }
}

export function fmtRateBytes(bytes: number) {
  return fmtSizeBytes(bytes) + "/s";
}
