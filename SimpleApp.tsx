import React, { useState } from 'react';
import { StyleSheet, Text, TextInput, View, Pressable, Share, Alert, ScrollView } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import * as Linking from 'expo-linking';
import { Buffer } from 'buffer';
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import { scrypt } from 'scrypt-js';

if (typeof global.Buffer === 'undefined') {
  global.Buffer = Buffer;
}

const SALT_LEN = 16;
const NONCE_LEN = 24;
const KEY_LEN = 32;
const SCRYPT_N = 2 ** 12;
const SCRYPT_r = 8;
const SCRYPT_p = 1;

const toBase64 = (u8: Uint8Array): string => Buffer.from(u8).toString('base64');
const fromBase64 = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, 'base64'));

async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const pw = new TextEncoder().encode(password);
  return new Uint8Array(await scrypt(pw, salt, SCRYPT_N, SCRYPT_r, SCRYPT_p, KEY_LEN));
}

async function encryptToBase64(plaintext: string, password: string): Promise<string> {
  try {
    const salt = new Uint8Array(await Crypto.getRandomBytesAsync(SALT_LEN));
    const nonce = new Uint8Array(await Crypto.getRandomBytesAsync(NONCE_LEN));
    const key = await deriveKey(password, salt);
    const msg = new TextEncoder().encode(plaintext);

    const box = nacl.secretbox(msg, nonce, key);
    if (!box) {
      throw new Error('Fallo en el cifrado');
    }
    
    const packed = new Uint8Array(salt.length + nonce.length + box.length);
    packed.set(salt, 0);
    packed.set(nonce, salt.length);
    packed.set(box, salt.length + nonce.length);
    return toBase64(packed);
  } catch (error) {
    console.error('Error en encryptToBase64:', error);
    throw error;
  }
}

async function decryptFromBase64(b64: string, password: string): Promise<string> {
  try {
    const all = fromBase64(b64);
    if (all.length <= SALT_LEN + NONCE_LEN + 16) {
      throw new Error('Texto cifrado demasiado corto');
    }

    const salt = all.slice(0, SALT_LEN);
    const nonce = all.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
    const box = all.slice(SALT_LEN + NONCE_LEN);
    const key = await deriveKey(password, salt);

    const plain = nacl.secretbox.open(box, nonce, key);
    if (!plain) {
      throw new Error('Contraseña incorrecta o texto corrupto');
    }
    return new TextDecoder().decode(plain);
  } catch (error) {
    console.error('Error en decryptFromBase64:', error);
    throw error;
  }
}

export default function SimpleApp() {
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [cipher, setCipher] = useState('');
  const [plainOut, setPlainOut] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  console.log('🔥 SimpleApp component rendering!');
  console.log('📱 Component state:', { message: message.length, password: password.length });

  const onEncryptShare = async () => {
    console.log('🔐 Encrypt button pressed');
    
    if (!message.trim() || !password.trim()) {
      Alert.alert('Error', 'Por favor ingresa tanto el mensaje como la contraseña');
      return;
    }
    
    setIsLoading(true);
    
    try {
      const b64 = await encryptToBase64(message, password);
      setCipher(b64);
      await Clipboard.setStringAsync(b64);
      
      setIsLoading(false);
      Alert.alert('✅ Éxito', 'Mensaje cifrado y copiado al portapapeles');
      
      Share.share({ 
        message: b64,
        title: 'Mensaje cifrado'
      }).catch((error) => {
        console.log('Share cancelado:', error?.message);
      });
      
    } catch (e: any) {
      console.error('❌ Error:', e?.message);
      Alert.alert('Error', e?.message ?? 'Fallo al cifrar el mensaje');
      setIsLoading(false);
    }
  };

  const onDecrypt = async () => {
    if (!cipher.trim() || !password.trim()) {
      Alert.alert('Error', 'Por favor ingresa tanto el texto cifrado como la contraseña');
      return;
    }
    
    setIsLoading(true);
    try {
      const pt = await decryptFromBase64(cipher.trim(), password);
      setPlainOut(pt);
    } catch (error: any) {
      console.error('Error en descifrado:', error);
      setPlainOut('ERROR: ' + (error?.message || 'Contraseña incorrecta o texto corrupto'));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>🔐 Secure Share - WORKING!</Text>
      
      <Text style={styles.label}>Mensaje</Text>
      <TextInput
        style={styles.input}
        value={message}
        onChangeText={setMessage}
        placeholder="Escribe tu mensaje..."
        multiline
      />

      <Text style={styles.label}>Contraseña</Text>
      <TextInput
        style={styles.input}
        value={password}
        onChangeText={setPassword}
        placeholder="Contraseña"
        secureTextEntry
      />

      <Pressable 
        style={[styles.button, isLoading && styles.buttonDisabled]} 
        onPress={onEncryptShare}
        disabled={isLoading}
      >
        <Text style={styles.buttonText}>
          {isLoading ? 'Cifrando...' : '🚀 Cifrar y compartir'}
        </Text>
      </Pressable>

      <Text style={styles.label}>Texto cifrado</Text>
      <TextInput
        style={styles.input}
        value={cipher}
        onChangeText={setCipher}
        placeholder="Pega aquí el texto cifrado..."
        multiline
      />

      <Pressable 
        style={[styles.button, isLoading && styles.buttonDisabled]} 
        onPress={onDecrypt}
        disabled={isLoading}
      >
        <Text style={styles.buttonText}>
          {isLoading ? 'Descifrando...' : '🔓 Descifrar'}
        </Text>
      </Pressable>

      <Text style={styles.label}>Resultado</Text>
      <Text style={styles.result}>
        {plainOut || 'El resultado aparecerá aquí...'}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 30,
    color: '#333',
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 8,
    marginTop: 16,
    color: '#333',
  },
  input: {
    borderWidth: 2,
    borderColor: '#3b82f6',
    borderRadius: 12,
    padding: 15,
    fontSize: 16,
    backgroundColor: '#fff',
    minHeight: 50,
  },
  button: {
    backgroundColor: '#3b82f6',
    padding: 15,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 20,
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  result: {
    borderWidth: 2,
    borderColor: '#10b981',
    borderRadius: 12,
    padding: 15,
    fontSize: 16,
    backgroundColor: '#fff',
    minHeight: 60,
    color: '#333',
  },
});

