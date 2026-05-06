import { Center, CenterProps, Loader, LoaderProps } from "@mantine/core";

export function LoadingScreen({
  size = "xl",
  mt = "30vh",
  ...centerProps
}: {
  size?: LoaderProps["size"];
} & CenterProps) {
  return (
    <Center mt={mt} {...centerProps}>
      <Loader size={size} />
    </Center>
  );
}
