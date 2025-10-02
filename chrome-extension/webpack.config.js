import path from 'path';
import { fileURLToPath } from 'url';
import CopyPlugin from 'copy-webpack-plugin';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default (env, argv) => {
  const isDev = argv.mode === 'development';
  
  return {
    entry: {
      content: './src/content.ts',
      background: './src/background.ts',
      popup: './src/popup.ts'
    },
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: {
            loader: 'ts-loader',
            options: {
              transpileOnly: isDev, // Skip type checking in dev for speed
              compilerOptions: {
                sourceMap: isDev,
              },
            },
          },
          exclude: /node_modules/,
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
    },
    output: {
      filename: '[name].js',
      path: path.resolve(process.cwd(), 'dist'),
      clean: !isDev, // Don't clean in dev mode
    },
    optimization: {
      minimize: !isDev,
    },
    devtool: isDev ? 'source-map' : false,
    cache: {
      type: 'filesystem',
      buildDependencies: {
        config: [__filename],
      },
    },
    plugins: [
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: 'manifest.json' },
          { from: 'src/popup.html', to: 'popup.html' },
          { from: 'icons', to: 'icons', noErrorOnMissing: true },
        ],
      }),
    ],
  };
};
