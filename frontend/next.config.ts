import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Traces the modules the server actually imports and emits a self-contained
  // bundle, so the runtime image carries neither node_modules nor the source.
  output: "standalone",
};

export default nextConfig;
