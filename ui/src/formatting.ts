export function fmtDate(d: Date) {
  const hours = d.getHours();
  const minutes = d.getMinutes();
  return `${fmtMonth(d.getMonth())} ${d.getDate()} ${
    hours > 9 ? hours : "0" + hours
  }:${minutes > 9 ? minutes : "0" + minutes}`;
}

export function fmtUtcDate(d: Date) {
  const hours = d.getUTCHours();
  const minutes = d.getUTCMinutes();
  return `${fmtMonth(d.getUTCMonth())} ${d.getUTCDate()} ${
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

export function fmtDuration(startTs: number, endTs: number) {
  const start = new Date(startTs);
  const end = new Date(endTs);
  const durr = end.getTime() - start.getTime();
  const seconds = durr / 1000;
  const minutes = Math.floor(seconds / 60);
  const remaining_seconds = seconds % 60;
  return `${
    minutes > 0 ? `${minutes} minute${minutes > 1 ? "s" : ""} ` : ""
  }${remaining_seconds.toFixed(minutes > 0 ? 0 : 1)} seconds`;
}

export function fmtUpperCamelcase(input: string) {
  return input.match(/[A-Z][a-z]+|[0-9]+/g)?.join(" ") ?? input;
}

/// list_all_items => List All Items
export function fmtSnakeCaseToUpperSpaceCase(snake: string) {
  if (snake.length === 0) return "";
  return snake
    .split("_")
    .map((item) => item[0].toUpperCase() + item.slice(1))
    .join(" ");
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
