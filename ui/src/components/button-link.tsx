import { Button, ButtonProps } from "@mantine/core";
import { Link } from "react-router-dom";

export interface ButtonLinkProps extends ButtonProps {
  to: string;
}

export function ButtonLink({ to, ...props }: ButtonLinkProps) {
  return (
    <Button
      variant="subtle"
      px="xs"
      fz="sm"
      className="hover-underline"
      renderRoot={(props) => <Link to={to} target="_blank" {...props} />}
      {...props}
    />
  );
}
