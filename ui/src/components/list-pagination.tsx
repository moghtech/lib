import { Group, Pagination, PaginationRootProps } from "@mantine/core";

export interface ListPaginationProps extends Omit<
  Omit<Omit<PaginationRootProps, "total">, "value">,
  "onChange"
> {
  page: number;
  setPage: (page: number) => void;
  count: number;
  /** The number of entries in a full page */
  pageSize: number;
}

/**
 * Pagination controls for list calls.
 */
export function ListPagination({
  page,
  setPage,
  count,
  pageSize,
  ...props
}: ListPaginationProps) {
  if (count < pageSize && page === 0) return null;
  return (
    <Pagination.Root
      total={count >= pageSize ? page + 2 : page + 1}
      value={page + 1}
      onChange={(page) => setPage(page - 1)}
      {...props}
    >
      <Group gap="0.2rem" justify="center">
        <Pagination.First aria-label="First page" />
        <Pagination.Previous aria-label="Previous page" />
        <Pagination.Items />
        <Pagination.Next aria-label="Next page" />
      </Group>
    </Pagination.Root>
  );
}
