export type ColorIntention =
  "Good" | "Neutral" | "Warning" | "Critical" | "Unknown" | "None";

export function hexColorByIntention(intention: ColorIntention) {
  switch (intention) {
    case "Good":
      return "#22C55E";
    case "Neutral":
      return "#3B82F6";
    case "Warning":
      return "#EAB308";
    case "Critical":
      return "#EF0044";
    case "Unknown":
      return "#A855F7";
    case "None":
      return undefined;
  }
}
