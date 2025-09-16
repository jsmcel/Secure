import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

console.log('🔥 TestApp.tsx loading...');

export default function TestApp() {
  console.log('🔥 TestApp component rendering!');
  
  return (
    <View style={styles.container}>
      <Text style={styles.text}>🔥 TEST APP WORKING!</Text>
      <Text style={styles.text}>If you see this, the app is loading correctly</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f0f0f0',
    padding: 20,
  },
  text: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#333',
    textAlign: 'center',
    marginBottom: 10,
  },
});
