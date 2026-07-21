// Type support for Vite `?worker` imports (see components/monaco/init.ts).
declare module "*?worker" {
  const WorkerFactory: new (options?: { name?: string }) => Worker;
  export default WorkerFactory;
}
