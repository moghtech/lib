import { Button, ButtonProps } from "@mantine/core";
import { ChevronLeft } from "lucide-react";
import { Link } from "react-router-dom";

export interface BackButtonProps extends ButtonProps {
  to?: string | number;
}

export function BackButton({ to = -1, ...props }: BackButtonProps) {
  return (
    <Button
      leftSection={<ChevronLeft size="1rem" />}
      renderRoot={(props) => <Link to={to} {...props} />}
      {...props}
    >
      Back
    </Button>
  );
}
