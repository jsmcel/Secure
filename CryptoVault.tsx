import React, { useState, useRef } from 'react';
import { StyleSheet, Text, TextInput, View, Pressable, Share, Alert, ScrollView, Animated, StatusBar, Platform } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import { Buffer } from 'buffer';
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import { scrypt } from 'scrypt-js';
import { encryptV2, decryptAuto, getKdfInfo } from './crypto-v2';

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
  const salt = new Uint8Array(await Crypto.getRandomBytesAsync(SALT_LEN));
  const nonce = new Uint8Array(await Crypto.getRandomBytesAsync(NONCE_LEN));
  const key = await deriveKey(password, salt);
  const msg = new TextEncoder().encode(plaintext);
  const box = nacl.secretbox(msg, nonce, key);
  if (!box) throw new Error('Encryption failed');
  
  const packed = new Uint8Array(salt.length + nonce.length + box.length);
  packed.set(salt, 0);
  packed.set(nonce, salt.length);
  packed.set(box, salt.length + nonce.length);
  return toBase64(packed);
}

async function decryptFromBase64(b64: string, password: string): Promise<string> {
  const all = fromBase64(b64);
  if (all.length <= SALT_LEN + NONCE_LEN + 16) {
    throw new Error('Encrypted text too short');
  }
  const salt = all.slice(0, SALT_LEN);
  const nonce = all.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
  const box = all.slice(SALT_LEN + NONCE_LEN);
  const key = await deriveKey(password, salt);
  const plain = nacl.secretbox.open(box, nonce, key);
  if (!plain) throw new Error('Incorrect password or corrupted data');
  return new TextDecoder().decode(plain);
}

async function tripleEncryptV2(seedPhrase: string, pass1: string, pass2: string, pass3: string): Promise<string> {
  console.log('🔐🔐🔐 Starting v2 triple encryption with Argon2id...');
  const layer1 = await encryptV2(seedPhrase, pass1);
  console.log('✅ Layer 1 complete (v2)');
  const layer2 = await encryptV2(layer1, pass2);
  console.log('✅ Layer 2 complete (v2)');
  const layer3 = await encryptV2(layer2, pass3);
  console.log('✅ Layer 3 complete (v2) - Triple encryption done');
  return layer3;
}

interface CryptoVaultProps {
  onBack?: () => void;
}

export default function CryptoVault({ onBack }: CryptoVaultProps) {
  const [seedPhrase, setSeedPhrase] = useState('');
  const [password1, setPassword1] = useState('');
  const [password2, setPassword2] = useState('');
  const [password3, setPassword3] = useState('');
  const [encryptedOutput, setEncryptedOutput] = useState('');
  const [decryptedSeed, setDecryptedSeed] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [activeTab, setActiveTab] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [decryptStep, setDecryptStep] = useState(1);
  const [tempData1, setTempData1] = useState('');
  const [tempData2, setTempData2] = useState('');

  const fadeAnim = useRef(new Animated.Value(0)).current;
  
  React.useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 1000,
      useNativeDriver: true,
    }).start();
  }, []);

  const switchTab = (tab: 'encrypt' | 'decrypt') => {
    if (tab === 'decrypt') {
      // Clear all sensitive data when entering decrypt
      setPassword1('');
      setPassword2('');
      setPassword3('');
      setEncryptedOutput('');
      setDecryptedSeed('');
      setTempData1('');
      setTempData2('');
      setDecryptStep(1);
    }
    setActiveTab(tab);
  };

  const onTripleEncrypt = async () => {
    console.log('🔥 Triple encrypt button pressed');
    
    if (!seedPhrase.trim() || !password1.trim() || !password2.trim() || !password3.trim()) {
      Alert.alert('Error', 'Please complete all fields');
      return;
    }

    setIsLoading(true);
    try {
      const result = await tripleEncryptV2(seedPhrase, password1, password2, password3);
      setEncryptedOutput(result);
      await Clipboard.setStringAsync(result);
      
      // Show KDF info
      const kdfInfo = getKdfInfo(result);
      const kdfText = kdfInfo ? `${kdfInfo.kdfId.toUpperCase()}` : 'UNKNOWN';
      
      Alert.alert(
        '🔐🔐🔐 v2 Triple Encryption Success', 
        'Your seed phrase is protected with 3 layers using enterprise-grade security.\n\n' +
        `🔐 KDF: ${kdfText} (OWASP compliant)\n` +
        '🌐 OUTER LAYER: You can store this text ANYWHERE PUBLIC\n' +
        '📋 Already copied to clipboard'
      );

    } catch (e: any) {
      Alert.alert('Error', e?.message ?? 'Triple encryption failed');
    } finally {
      setIsLoading(false);
    }
  };

  const onStepDecrypt = async () => {
    setIsLoading(true);
    
    try {
      if (decryptStep === 1) {
        if (!encryptedOutput.trim() || !password3.trim()) {
          Alert.alert('Error', 'Need encrypted text and password 3');
          return;
        }
        const result = await decryptAuto(encryptedOutput.trim(), password3);
        setTempData1(result);
        setDecryptStep(2);
        setPassword3('');
        Alert.alert('🔓 Step 1 Complete', 'Layer 3 decrypted. Now enter password 2');
        
      } else if (decryptStep === 2) {
        if (!tempData1.trim() || !password2.trim()) {
          Alert.alert('Error', 'Need password 2');
          return;
        }
        const result = await decryptAuto(tempData1, password2);
        setTempData2(result);
        setDecryptStep(3);
        setPassword2('');
        setTempData1('');
        Alert.alert('🔓 Step 2 Complete', 'Layer 2 decrypted. Now enter password 1 (most secret)');
        
      } else if (decryptStep === 3) {
        if (!tempData2.trim() || !password1.trim()) {
          Alert.alert('Error', 'Need password 1 (most secret)');
          return;
        }
        const result = await decryptAuto(tempData2, password1);
        setDecryptedSeed(result);
        setPassword1('');
        setTempData2('');
        setEncryptedOutput('');
        
        Alert.alert(
          '🎉🌱🎉 SEED PHRASE RECOVERED 🎉🌱🎉', 
          '!!!TOTAL SUCCESS!!!\n\n' +
          '🔓🔓🔓 TRIPLE DECRYPTION COMPLETED\n' +
          '🌱 YOUR SEED PHRASE IS VISIBLE BELOW'
        );
      }
      
    } catch (error: any) {
      Alert.alert('Error', `Step ${decryptStep} failed: ${error?.message || 'Incorrect password'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const resetAll = () => {
    setDecryptStep(1);
    setTempData1('');
    setTempData2('');
    setDecryptedSeed('');
    setEncryptedOutput('');
    setPassword1('');
    setPassword2('');
    setPassword3('');
    Alert.alert('🔄 Reset Complete', 'All data cleared');
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && text.trim()) {
        setEncryptedOutput(text.trim());
      } else {
        Alert.alert('Info', 'Clipboard is empty');
      }
    } catch (error) {
      Alert.alert('Error', 'Could not paste from clipboard');
    }
  };

  const theme = isDarkMode ? darkTheme : lightTheme;

  return (
    <View style={[styles.container, { backgroundColor: theme.background }]}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      
      <Animated.View style={[styles.header, { backgroundColor: theme.surface }, { opacity: fadeAnim }]}>
        <View style={styles.headerContent}>
          <View style={styles.headerLeft}>
            {onBack && (
              <Pressable 
                style={[styles.backButton, { backgroundColor: theme.primary }]}
                onPress={onBack}
              >
                <Text style={styles.backButtonText}>← Messages</Text>
              </Pressable>
            )}
            <View>
              <Text style={[styles.title, { color: theme.text }]}>🔐🔐🔐 CryptoVault</Text>
              <Text style={[styles.subtitle, { color: theme.textSecondary }]}>Triple-Layer Seed Protection v2</Text>
              <Text style={[styles.kdfBadge, { color: theme.primary }]}>
                🛡️ Argon2id + scrypt (OWASP)
              </Text>
            </View>
          </View>
          <Pressable 
            style={[styles.themeToggle, { backgroundColor: theme.primary }]}
            onPress={() => setIsDarkMode(!isDarkMode)}
          >
            <Text style={styles.themeToggleText}>{isDarkMode ? '☀️' : '🌙'}</Text>
          </Pressable>
        </View>
      </Animated.View>

      <View style={[styles.tabContainer, { backgroundColor: theme.surface }]}>
        <Pressable 
          style={[styles.tab, activeTab === 'encrypt' && { backgroundColor: theme.primary }]}
          onPress={() => switchTab('encrypt')}
        >
          <Text style={[styles.tabText, { color: activeTab === 'encrypt' ? '#ffffff' : theme.textSecondary }]}>
            🔒 Protect Seed
          </Text>
        </Pressable>
        <Pressable 
          style={[styles.tab, activeTab === 'decrypt' && { backgroundColor: theme.primary }]}
          onPress={() => switchTab('decrypt')}
        >
          <Text style={[styles.tabText, { color: activeTab === 'decrypt' ? '#ffffff' : theme.textSecondary }]}>
            🔓 Recover Seed
          </Text>
        </Pressable>
      </View>

      <ScrollView style={styles.content} contentContainerStyle={styles.scrollContent}>
        {activeTab === 'encrypt' ? (
          <Animated.View style={[styles.section, { opacity: fadeAnim }]}>
            <View style={[styles.card, { backgroundColor: theme.surface }]}>
              <Text style={[styles.sectionTitle, { color: theme.text }]}>🌱 Your Seed Phrase</Text>
              <TextInput
                style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.border }]}
                value={seedPhrase}
                multiline
                onChangeText={setSeedPhrase}
                placeholder="Enter your seed phrase here..."
                placeholderTextColor={theme.textSecondary}
                editable={!isLoading}
              />
              
              <Text style={[styles.sectionTitle, { color: theme.text }]}>🔐 Password 1</Text>
              <TextInput
                style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.border }]}
                value={password1}
                onChangeText={setPassword1}
                placeholder="Enter password 1"
                placeholderTextColor={theme.textSecondary}
                secureTextEntry
                editable={!isLoading}
              />

              <Text style={[styles.sectionTitle, { color: theme.text }]}>🔐 Password 2</Text>
              <TextInput
                style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.border }]}
                value={password2}
                onChangeText={setPassword2}
                placeholder="Enter password 2"
                placeholderTextColor={theme.textSecondary}
                secureTextEntry
                editable={!isLoading}
              />

              <Text style={[styles.sectionTitle, { color: theme.text }]}>🔐 Password 3</Text>
              <TextInput
                style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.border }]}
                value={password3}
                onChangeText={setPassword3}
                placeholder="Enter password 3"
                placeholderTextColor={theme.textSecondary}
                secureTextEntry
                editable={!isLoading}
              />

              <Pressable 
                style={[styles.button, { backgroundColor: theme.primary }, isLoading && styles.buttonDisabled]} 
                onPress={onTripleEncrypt}
                disabled={isLoading}
              >
                <Text style={styles.buttonText}>
                  {isLoading ? '🔐🔐🔐 Triple Encrypting...' : '🚀 Protect with Triple Layer'}
                </Text>
              </Pressable>

              {encryptedOutput && (
                <View style={styles.outputSection}>
                  <Text style={[styles.sectionTitle, { color: theme.success }]}>🌐 PUBLIC-SAFE OUTPUT</Text>
                  <Text style={[styles.infoText, { color: theme.textSecondary }]}>✅ Safe to store anywhere public!</Text>
                  <View style={[styles.outputCard, { backgroundColor: theme.inputBackground, borderColor: theme.success }]}>
                    <Text selectable style={[styles.outputText, { color: theme.text }]}>{encryptedOutput}</Text>
                  </View>
                </View>
              )}
            </View>
          </Animated.View>
        ) : (
          <Animated.View style={[styles.section, { opacity: fadeAnim }]}>
            <View style={[styles.card, { backgroundColor: theme.surface }]}>
              <View style={[styles.progressContainer, { backgroundColor: theme.inputBackground, borderColor: theme.border }]}>
                <Text style={[styles.progressTitle, { color: theme.text }]}>🔓 Decrypt Progress: Step {decryptStep}/3</Text>
              </View>

              <Text style={[styles.sectionTitle, { color: theme.text }]}>
                {decryptStep === 1 && '🌐 Step 1: Encrypted Data'}
                {decryptStep === 2 && '🔐 Step 2: Password 2'}
                {decryptStep === 3 && '🔒 Step 3: Password 1 (Most Secret)'}
              </Text>

              {decryptStep === 1 && (
                <>
                  <TextInput
                    style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.primary }]}
                    value={encryptedOutput}
                    multiline
                    onChangeText={setEncryptedOutput}
                    placeholder="Paste your encrypted data here..."
                    placeholderTextColor={theme.textSecondary}
                    editable={!isLoading}
                  />
                  <View style={styles.actionButtons}>
                    <Pressable 
                      style={[styles.button, styles.secondaryButton, { borderColor: theme.border }]}
                      onPress={pasteFromClipboard}
                      disabled={isLoading}
                    >
                      <Text style={[styles.secondaryButtonText, { color: theme.primary }]}>📋 Paste</Text>
                    </Pressable>
                  </View>
                  <Text style={[styles.sectionTitle, { color: theme.text }]}>🔐 Password 3</Text>
                  <TextInput
                    style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.primary }]}
                    value={password3}
                    onChangeText={setPassword3}
                    placeholder="Enter password 3"
                    placeholderTextColor={theme.textSecondary}
                    secureTextEntry
                    editable={!isLoading}
                  />
                </>
              )}

              {decryptStep === 2 && (
                <>
                  <View style={[styles.completedStep, { backgroundColor: theme.success + '20', borderColor: theme.success }]}>
                    <Text style={[styles.completedStepText, { color: theme.success }]}>✅ Layer 3 Successfully Decrypted</Text>
                  </View>
                  <TextInput
                    style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.primary }]}
                    value={password2}
                    onChangeText={setPassword2}
                    placeholder="Enter password 2"
                    placeholderTextColor={theme.textSecondary}
                    secureTextEntry
                    editable={!isLoading}
                  />
                </>
              )}

              {decryptStep === 3 && (
                <>
                  <View style={[styles.completedStep, { backgroundColor: theme.success + '20', borderColor: theme.success }]}>
                    <Text style={[styles.completedStepText, { color: theme.success }]}>✅ Layer 3 & 2 Successfully Decrypted</Text>
                  </View>
                  <View style={[styles.warningBox, { backgroundColor: theme.error + '20', borderColor: theme.error }]}>
                    <Text style={[styles.warningText, { color: theme.error }]}>⚠️ FINAL STEP: This will reveal your seed phrase!</Text>
                  </View>
                  <TextInput
                    style={[styles.input, { backgroundColor: theme.inputBackground, color: theme.text, borderColor: theme.error }]}
                    value={password1}
                    onChangeText={setPassword1}
                    placeholder="Enter password 1"
                    placeholderTextColor={theme.textSecondary}
                    secureTextEntry
                    editable={!isLoading}
                  />
                </>
              )}

              <View style={styles.actionButtons}>
                <Pressable 
                  style={[styles.button, styles.secondaryButton, { borderColor: theme.error }]}
                  onPress={resetAll}
                  disabled={isLoading}
                >
                  <Text style={[styles.secondaryButtonText, { color: theme.error }]}>🔄 Reset</Text>
                </Pressable>
                <Pressable 
                  style={[styles.button, { backgroundColor: decryptStep === 3 ? theme.error : theme.primary }, isLoading && styles.buttonDisabled]}
                  onPress={onStepDecrypt}
                  disabled={isLoading}
                >
                  <Text style={styles.buttonText}>
                    {isLoading ? `🔓 Step ${decryptStep}...` : 
                     decryptStep === 1 ? '🌐 Decrypt Step 1' :
                     decryptStep === 2 ? '🔐 Decrypt Step 2' :
                     '🌱 REVEAL SEED!'}
                  </Text>
                </Pressable>
              </View>

              {decryptedSeed && (
                <View style={styles.resultSection}>
                  {!decryptedSeed.startsWith('ERROR:') && (
                    <View style={[styles.successBanner, { backgroundColor: theme.success }]}>
                      <Text style={styles.successBannerText}>🎉🎉🎉 TRIPLE DECRYPT SUCCESS! 🎉🎉🎉</Text>
                    </View>
                  )}
                  
                  <Text style={[styles.sectionTitle, { color: theme.success, fontSize: 22, textAlign: 'center' }]}>
                    🌱🌱🌱 YOUR SEED PHRASE 🌱🌱🌱
                  </Text>
                  
                  <View style={[styles.resultCard, { backgroundColor: theme.success + '10', borderColor: theme.success, borderWidth: 4 }]}>
                    <Text selectable style={[styles.resultText, { color: theme.text, fontSize: 18, fontWeight: '700', textAlign: 'center' }]}>
                      {decryptedSeed}
                    </Text>
                  </View>
                </View>
              )}
            </View>
          </Animated.View>
        )}
      </ScrollView>
    </View>
  );
}

const lightTheme = {
  background: '#f8fafc',
  surface: '#ffffff',
  primary: '#3b82f6',
  text: '#1e293b',
  textSecondary: '#64748b',
  border: '#e2e8f0',
  inputBackground: '#ffffff',
  success: '#10b981',
  error: '#ef4444',
};

const darkTheme = {
  background: '#0f172a',
  surface: '#1e293b',
  primary: '#3b82f6',
  text: '#f1f5f9',
  textSecondary: '#94a3b8',
  border: '#334155',
  inputBackground: '#334155',
  success: '#10b981',
  error: '#ef4444',
};

const styles = StyleSheet.create({
  container: { flex: 1 },
  header: { paddingTop: 25, paddingHorizontal: 20, paddingBottom: 20, borderBottomLeftRadius: 24, borderBottomRightRadius: 24 },
  headerContent: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  backButton: {
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 20,
    marginRight: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  backButtonText: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '700',
  },
  title: { fontSize: 24, fontWeight: '800' },
  subtitle: { fontSize: 12, marginTop: 2, opacity: 0.8 },
  kdfBadge: {
    fontSize: 10,
    marginTop: 4,
    opacity: 0.9,
    fontWeight: '600',
  },
  themeToggle: { width: 40, height: 40, borderRadius: 20, justifyContent: 'center', alignItems: 'center' },
  themeToggleText: { fontSize: 16 },
  tabContainer: { flexDirection: 'row', margin: 16, padding: 4, borderRadius: 16 },
  tab: { flex: 1, paddingVertical: 12, paddingHorizontal: 16, borderRadius: 12, alignItems: 'center' },
  tabText: { fontSize: 14, fontWeight: '600' },
  content: { flex: 1 },
  scrollContent: { padding: 16 },
  section: { marginBottom: 20 },
  card: { borderRadius: 20, padding: 24 },
  sectionTitle: { fontSize: 16, fontWeight: '700', marginBottom: 12 },
  input: { borderWidth: 2, borderRadius: 16, paddingHorizontal: 20, paddingVertical: 16, fontSize: 16, marginBottom: 16, minHeight: 50 },
  button: { borderRadius: 16, paddingVertical: 16, paddingHorizontal: 24, alignItems: 'center', marginBottom: 12 },
  buttonText: { color: '#ffffff', fontSize: 16, fontWeight: '700' },
  secondaryButton: { backgroundColor: 'transparent', borderWidth: 2, flex: 1, marginRight: 8 },
  secondaryButtonText: { fontSize: 14, fontWeight: '600' },
  buttonDisabled: { opacity: 0.5 },
  actionButtons: { flexDirection: 'row' },
  outputSection: { marginTop: 20, paddingTop: 20, borderTopWidth: 1, borderTopColor: 'rgba(0,0,0,0.1)' },
  outputCard: { borderWidth: 2, borderRadius: 16, padding: 20, marginTop: 10 },
  outputText: { fontSize: 14 },
  progressContainer: { borderWidth: 2, borderRadius: 16, padding: 16, marginBottom: 20 },
  progressTitle: { fontSize: 16, fontWeight: '700', textAlign: 'center' },
  completedStep: { borderWidth: 2, borderRadius: 12, padding: 12, marginBottom: 16, alignItems: 'center' },
  completedStepText: { fontSize: 16, fontWeight: '700' },
  warningBox: { borderWidth: 2, borderRadius: 12, padding: 12, marginBottom: 16, alignItems: 'center' },
  warningText: { fontSize: 14, fontWeight: '700', textAlign: 'center' },
  resultSection: { marginTop: 20, paddingTop: 20, borderTopWidth: 1, borderTopColor: 'rgba(0,0,0,0.1)' },
  resultCard: { borderRadius: 16, padding: 20, marginBottom: 16, minHeight: 80 },
  resultText: { fontSize: 16, lineHeight: 24, fontWeight: '500' },
  successBanner: { borderRadius: 16, padding: 20, marginBottom: 20, alignItems: 'center' },
  successBannerText: { color: '#ffffff', fontSize: 18, fontWeight: '800', textAlign: 'center' },
  infoText: { fontSize: 14, marginBottom: 10 },
});