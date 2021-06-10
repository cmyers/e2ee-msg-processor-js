/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = {
  target: 'node',
  devtool: "source-map",
  externals: [nodeExternals()],
  entry: {
    index: './src/OmemoManager.ts',
    example: {
      dependOn: 'index',
      import: './src/example.ts'
    },
  },
  optimization: {
    splitChunks: {
      chunks: 'all',
    },
  },
  module: {
    rules: [
      {
        test: /\.ts?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },

    ],
  },
  resolve: {
    extensions: ['.ts'], 
  },
  output: {
    filename: '[name].bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
};