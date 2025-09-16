const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Configuración para manejar dependencias con polyfills
config.resolver.alias = {
  ...config.resolver.alias,
  'crypto': 'expo-crypto',
};

// Asegurar que los polyfills se incluyan
config.resolver.platforms = ['native', 'android', 'ios', 'web'];

module.exports = config;

