export type ColorIntention =
  | "Good"
  | "Neutral"
  | "Warning"
  | "Critical"
  | "Unknown"
  | "None";

export function colorByIntention(intention: ColorIntention) {
  switch (intention) {
    case "Good":
      return "green";
    case "Neutral":
      return "blue";
    case "Warning":
      return "yellow";
    case "Critical":
      return "red";
    case "Unknown":
      return "purple";
    case "None":
      return undefined;
  }
}

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
