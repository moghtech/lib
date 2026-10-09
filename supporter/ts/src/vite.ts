/**
 * The release date of an app's build, for its vite config:
 * `mogh_supporter/vite`, which loads nothing of the browser side.
 *
 * A supporter key covers the releases published up to a date (its
 * `c`), forever, so the badge compares the key with the date of the
 * release it runs in, never with the clock (`checkSupporterKey`'s
 * `releaseDate`). That date belongs to the release's source: the
 * `releaseDate` of the app's package.json, bumped together with its
 * `version`. Taken from the build environment instead, a rebuild of an
 * old release (a refreshed base image, a self built image) would get
 * the day of the build, and a key which covered the release would
 * lose its badge there.
 */

/** What `releaseDate` reads. */
export interface ReleaseDateOptions {
  /**
   * Vite's mode (`defineConfig(({ mode }) => ...)`): `production` for
   * `vite build`, `development` for the dev server, `test` for vitest.
   */
  mode: string;
  /**
   * The app's package.json, eg. `import packageJson from
   * "./package.json"`. Its `releaseDate` is the date, `YYYY-MM-DD`.
   */
  packageJson: { name?: unknown; releaseDate?: unknown } | null | undefined;
}

/**
 * Whether `text` is a `YYYY-MM-DD` date of the calendar: four digit
 * year, two digit month and day, and a day the month has.
 */
function isCalendarDate(text: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (match === null) return false;
  const [year, month, day] = match.slice(1).map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  // Out of range fields roll over (the 30th of February is in March),
  // and years below 100 are read as 19xx: neither comes back the same.
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

/**
 * The `YYYY-MM-DD` release date the supporter badge compares keys
 * with, for the app's vite config `define`, eg.:
 *
 * ```ts
 * import { releaseDate } from "mogh_supporter/vite";
 * import packageJson from "./package.json";
 *
 * export default defineConfig(({ mode }) => ({
 *   define: {
 *     __RELEASE_DATE__: JSON.stringify(releaseDate({ mode, packageJson })),
 *   },
 * }));
 * ```
 *
 * It is the `releaseDate` of `packageJson`, in every mode. Without one
 * a production build throws, so a release can't be built with the day
 * of the build; any other mode (the dev server, tests) falls back to
 * today, in UTC. A `releaseDate` which is no `YYYY-MM-DD` date of the
 * calendar throws in every mode.
 */
export function releaseDate({ mode, packageJson }: ReleaseDateOptions): string {
  const of =
    typeof packageJson?.name === "string"
      ? `the package.json of ${packageJson.name}`
      : "the app's package.json";
  const date = packageJson?.releaseDate;
  if (date === undefined) {
    if (mode === "production") {
      throw new Error(
        `No "releaseDate" in ${of}: a production build compares supporter keys with the date of its release, set with the version ("releaseDate": "YYYY-MM-DD"), never with the day of the build`,
      );
    }
    return new Date().toISOString().slice(0, 10);
  }
  if (typeof date !== "string" || !isCalendarDate(date)) {
    throw new Error(
      `The "releaseDate" of ${of} is not a YYYY-MM-DD calendar date: ${JSON.stringify(date)}`,
    );
  }
  return date;
}
