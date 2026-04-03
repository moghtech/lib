import { Button } from "@mantine/core";
import { ChevronDown, ChevronUp } from "lucide-react";

export function ShowHideButton({
  show,
  setShow,
}: {
  show: boolean;
  setShow: (show: boolean) => void;
}) {
  return (
    <Button
      variant="outline"
      onClick={(e) => {
        e.stopPropagation();
        setShow(!show);
      }}
      rightSection={
        show ? <ChevronUp size="1rem" /> : <ChevronDown size="1rem" />
      }
    >
      {show ? "Hide" : "Show"}
    </Button>
  );
}
