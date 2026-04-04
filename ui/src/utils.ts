/**
 * Does deep compare of 2 items, returning `true` if equal.
 *
 * - Functions: Always `true`
 * - Primitives: Returns direct `a === b`
 * - Arrays: Returns same items and ordering (recursive)
 * - Objects: Returns same keys / values (recursive)
 *
 * @param a Item a
 * @param b Item b
 * @returns a === b
 */
export function deepCompare(a: any, b: any) {
  // Short path for falsy. Important to catch typeof null === "object" edge case.
  if (!a || !b) {
    return a === b;
  }

  const ta = typeof a;
  const tb = typeof b;

  if (ta !== tb) return false;

  if (ta === "function") return true;

  if (ta === "object") {
    const ea = Object.entries(a);
    const kb = Object.keys(b);

    // Length not equal -> false
    if (ea.length !== kb.length) return false;

    for (const [key, va] of ea) {
      const vb = b[key];

      // Early return when any not equal
      if (!deepCompare(va, vb)) return false;
    }

    // If it gets through all, it's equal
    return true;
  }

  return a === b;
}

export function filterBySplit<T>(
  items: T[] | undefined,
  search: string,
  extract: (item: T) => string,
) {
  const split = search.toLowerCase().split(" ");
  return (
    (split.length
      ? items?.filter((item) => {
          const target = extract(item).toLowerCase();
          return split.every((term) => target.includes(term));
        })
      : items) ?? []
  );
}

export function filterMultitermBySplit<T>(
  items: T[] | undefined,
  search: string,
  extract: (item: T) => (string | undefined)[],
) {
  const split = search.toLowerCase().split(" ");
  return (
    (split.length
      ? items?.filter((item) => {
          const target = extract(item)
            .filter((str) => str)
            .map((str) => str!.toLowerCase());
          return split.every(
            (term) => target.findIndex((t) => t.includes(term)) !== -1,
          );
        })
      : items) ?? []
  );
}