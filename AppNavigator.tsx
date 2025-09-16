import React, { useState } from 'react';
import { StyleSheet, View, Pressable, Text, StatusBar } from 'react-native';
import App from './App';
import CryptoVault from './CryptoVault';

export default function AppNavigator() {
  const [currentApp, setCurrentApp] = useState<'messenger' | 'crypto'>('messenger');

  console.log('🔥 AppNavigator rendering, currentApp:', currentApp);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#1e293b" />
      
      <View style={styles.selector}>
        <Pressable 
          style={[styles.selectorButton, currentApp === 'messenger' && styles.selectorButtonActive]}
          onPress={() => setCurrentApp('messenger')}
        >
          <Text style={[styles.selectorText, currentApp === 'messenger' && styles.selectorTextActive]}>
            💬 Secure Messages
          </Text>
        </Pressable>
        
        <Pressable 
          style={[styles.selectorButton, currentApp === 'crypto' && styles.selectorButtonActive]}
          onPress={() => setCurrentApp('crypto')}
        >
          <Text style={[styles.selectorText, currentApp === 'crypto' && styles.selectorTextActive]}>
            🔐🔐🔐 Crypto Vault
          </Text>
        </Pressable>
      </View>

      <View style={styles.appContainer}>
        {currentApp === 'messenger' ? <App /> : <CryptoVault />}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1e293b',
  },
  selector: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    paddingVertical: 8,
    backgroundColor: '#1e293b',
    gap: 8,
  },
  selectorButton: {
    flex: 1,
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 12,
    backgroundColor: 'rgba(255,255,255,0.1)',
    alignItems: 'center',
  },
  selectorButtonActive: {
    backgroundColor: '#3b82f6',
  },
  selectorText: {
    color: 'rgba(255,255,255,0.7)',
    fontSize: 14,
    fontWeight: '600',
  },
  selectorTextActive: {
    color: '#ffffff',
  },
  appContainer: {
    flex: 1,
  },
});