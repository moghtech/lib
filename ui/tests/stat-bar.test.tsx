import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatBar } from "../src/components/stat-bar";
import { StatCell } from "../src/components/stat-cell";
import { renderWithProviders } from "./render";

describe("StatBar", () => {
  it.each([undefined, NaN, Infinity])(
    "shows N/A for an unknown percentage: %s",
    (percentage) => {
      renderWithProviders(
        <StatBar
          title="CPU"
          icon={null}
          percentage={percentage}
          warning={75}
          critical={90}
        />,
      );
      screen.getByText("N/A");
      expect(screen.queryByText(/%$/)).toBeNull();
    },
  );

  it("shows a known percentage", () => {
    renderWithProviders(
      <StatBar
        title="CPU"
        icon={null}
        percentage={42.5}
        warning={75}
        critical={90}
      />,
    );
    screen.getByText("42.50%");
  });
});

describe("StatCell", () => {
  it("shows N/A for an unknown value, NaN included", () => {
    renderWithProviders(<StatCell value={NaN} intent="Good" />);
    screen.getByText("N/A");
    expect(screen.queryByText("NaN%")).toBeNull();
  });
});
