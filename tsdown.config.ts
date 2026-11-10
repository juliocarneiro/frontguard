import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    cli: 'src/cli/bin.ts',
  },
  format: 'esm',
  platform: 'node',
  target: 'node22.18',
  dts: true,
  clean: true,
  sourcemap: false,
  publint: true,
});
