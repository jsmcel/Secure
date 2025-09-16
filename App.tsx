import React, { useState, useRef } from 'react';
import { StyleSheet, Text, TextInput, View, Pressable, Share, Alert, ScrollView, Animated, StatusBar, Platform } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import { Buffer } from 'buffer';
import 'react-native-get-random-values';
import * as Linking from 'expo-linking';
import nacl from 'tweetnacl';
import { scrypt } from 'scrypt-js';
import CryptoVault from './CryptoVault';
import { encryptV2, decryptAuto, getKdfInfo } from './crypto-v2';

if (typeof global.Buffer === 'undefined') {
  global.Buffer = Buffer;
}

const SALT_LEN = 16;
const NONCE_LEN = 24;
const KEY_LEN = 32;
const SCRYPT_N = 2 ** 12; // Optimized for mobile
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
      throw new Error('Encryption failed');
    }
    
    const packed = new Uint8Array(salt.length + nonce.length + box.length);
    packed.set(salt, 0);
    packed.set(nonce, salt.length);
    packed.set(box, salt.length + nonce.length);
    return toBase64(packed);
  } catch (error) {
    console.error('Error in encryptToBase64:', error);
    throw error;
  }
}

async function decryptFromBase64(b64: string, password: string): Promise<string> {
  try {
    const all = fromBase64(b64);
    if (all.length <= SALT_LEN + NONCE_LEN + 16) {
      throw new Error('Encrypted text too short');
    }

    const salt = all.slice(0, SALT_LEN);
    const nonce = all.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
    const box = all.slice(SALT_LEN + NONCE_LEN);
    const key = await deriveKey(password, salt);

    const plain = nacl.secretbox.open(box, nonce, key);
    if (!plain) {
      throw new Error('Incorrect password or corrupted data');
    }
    return new TextDecoder().decode(plain);
  } catch (error) {
    console.error('Error in decryptFromBase64:', error);
    throw error;
  }
}

export default function App() {
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [cipher, setCipher] = useState('');
  const [decryptPassword, setDecryptPassword] = useState('');
  const [plainOut, setPlainOut] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [activeTab, setActiveTab] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [showCryptoVault, setShowCryptoVault] = useState(false);
  
  const fadeAnim = useRef(new Animated.Value(0)).current;
  
  React.useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 1000,
      useNativeDriver: true,
    }).start();
  }, []);

  const onEncryptShare = async () => {
    if (!message.trim() || !password.trim()) {
      Alert.alert('Error', 'Please enter both message and password');
      return;
    }
    
    setIsLoading(true);
    try {
      console.log('🔐 Using v2 encryption with Argon2id/scrypt...');
      const startTime = Date.now();
      const b64 = await encryptV2(message, password);
      const endTime = Date.now();
      console.log(`⚡ Encryption took ${endTime - startTime}ms`);
      setCipher(b64);
      await Clipboard.setStringAsync(b64);
      
      // Show KDF info for transparency
      const kdfInfo = getKdfInfo(b64);
      const kdfText = kdfInfo ? kdfInfo.kdfId.toUpperCase() : 'UNKNOWN';
      const kdfDetails = kdfInfo ? 
        (kdfInfo.kdfId === 'argon2id' ? 
          `Argon2id (${kdfInfo.config.m}KiB, t=${kdfInfo.config.t}, p=${kdfInfo.config.p})` :
          `scrypt (N=${kdfInfo.config.N}, r=${kdfInfo.config.r}, p=${kdfInfo.config.s_p})`
        ) : 'Legacy format';
      
      setIsLoading(false);
      Alert.alert(
        '✅ Encryption Success', 
        `Message encrypted and copied to clipboard\n\n` +
        `🔐 KDF Used: ${kdfText}\n` +
        `⚙️ Parameters: ${kdfDetails}\n` +
        `⏱️ Time: ${endTime - startTime}ms`
      );
      
      Share.share({ 
        message: b64,
        title: 'Encrypted Message'
      }).catch(() => {});
      
    } catch (e: any) {
      Alert.alert('Error', e?.message ?? 'Failed to encrypt message');
      setIsLoading(false);
    }
  };

  const onDecrypt = async () => {
    if (!cipher.trim() || !decryptPassword.trim()) {
      Alert.alert('Error', 'Please enter both encrypted text and password');
      return;
    }
    
    setIsLoading(true);
    try {
      console.log('🔓 Using auto-decrypt (v2 + legacy fallback)...');
      
      // Try to get KDF info first
      const kdfInfo = getKdfInfo(cipher.trim());
      if (kdfInfo) {
        console.log(`📋 Detected format: v2 with ${kdfInfo.kdfId.toUpperCase()}`);
        const params = kdfInfo.kdfId === 'argon2id' ? 
          `m=${kdfInfo.config.m}KiB, t=${kdfInfo.config.t}, p=${kdfInfo.config.p}` :
          `N=${kdfInfo.config.N}, r=${kdfInfo.config.r}, p=${kdfInfo.config.s_p}`;
        console.log(`⚙️ KDF params: ${params}`);
      } else {
        console.log('📋 Detected format: LEGACY (old scrypt)');
      }
      
      const decryptStart = Date.now();
      const pt = await decryptAuto(cipher.trim(), decryptPassword);
      const decryptEnd = Date.now();
      setPlainOut(pt);
      
      // Show detailed format info
      const formatText = kdfInfo ? 
        `v2 format using ${kdfInfo.kdfId.toUpperCase()}` : 
        'legacy format (old scrypt)';
      console.log(`✅ Decrypted using ${formatText} in ${decryptEnd - decryptStart}ms`);
      
    } catch (error: any) {
      setPlainOut('ERROR: ' + (error?.message || 'Incorrect password or corrupted text'));
    } finally {
      setIsLoading(false);
    }
  };

  const openWhatsApp = async () => {
    if (!cipher.trim()) {
      Alert.alert('Error', 'No encrypted text to share');
      return;
    }
    
    try {
      const url = `whatsapp://send?text=${encodeURIComponent(cipher)}`;
      const supported = await Linking.canOpenURL(url);
      if (supported) {
        await Linking.openURL(url);
      } else {
        await Share.share({ 
          message: cipher,
          title: 'Share encrypted message'
        });
      }
    } catch (error) {
      Alert.alert('Error', 'Could not open WhatsApp');
    }
  };

  const openTelegram = async () => {
    if (!cipher.trim()) {
      Alert.alert('Error', 'No encrypted text to share');
      return;
    }
    
    try {
      const tgDeep = `tg://msg?text=${encodeURIComponent(cipher)}`;
      const tgWeb = `https://t.me/share/url?url=&text=${encodeURIComponent(cipher)}`;
      const supported = await Linking.canOpenURL(tgDeep);
      if (supported) {
        await Linking.openURL(tgDeep);
      } else {
        await Linking.openURL(tgWeb);
      }
    } catch (error) {
      Alert.alert('Error', 'Could not open Telegram');
    }
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && text.trim()) {
        setCipher(text.trim());
      } else {
        Alert.alert('Info', 'Clipboard is empty');
      }
    } catch (error) {
      Alert.alert('Error', 'Could not paste from clipboard');
    }
  };

  const copyPlain = async () => {
    if (!plainOut || plainOut.startsWith('ERROR:')) {
      Alert.alert('Error', 'No valid result to copy');
      return;
    }
    
    try {
      await Clipboard.setStringAsync(plainOut);
      Alert.alert('Success', 'Result copied to clipboard');
    } catch (error) {
      Alert.alert('Error', 'Could not copy to clipboard');
    }
  };

  const theme = isDarkMode ? darkTheme : lightTheme;

  // Show CryptoVault if button was pressed
  if (showCryptoVault) {
    return <CryptoVault onBack={() => setShowCryptoVault(false)} />;
  }

  return (
    <View style={[styles.container, { backgroundColor: theme.background }]}>
      <StatusBar 
        barStyle={isDarkMode ? 'light-content' : 'dark-content'} 
        backgroundColor={theme.background}
      />
      
      <Animated.View 
        style={[
          styles.header, 
          { backgroundColor: theme.surface },
          { opacity: fadeAnim }
        ]}
      >
        <View style={styles.headerContent}>
          <View>
            <Text style={[styles.title, { color: theme.text }]}>
              {showCryptoVault ? '🔐🔐🔐 CryptoVault' : '💬 Secure Messages'}
            </Text>
            <Text style={[styles.subtitle, { color: theme.textSecondary }]}>
              {showCryptoVault ? 'Triple-Layer Seed Protection' : 'End-to-end encryption v2'}
            </Text>
            <Text style={[styles.kdfBadge, { color: theme.primary }]}>
              🛡️ Argon2id + scrypt (OWASP)
            </Text>
          </View>
          <Pressable 
            style={[styles.themeToggle, { backgroundColor: theme.primary }]}
            onPress={() => setIsDarkMode(!isDarkMode)}
          >
            <Text style={styles.themeToggleText}>{isDarkMode ? '☀️' : '🌙'}</Text>
          </Pressable>
        </View>
      </Animated.View>

      {!showCryptoVault && (
        <View style={[styles.tabContainer, { backgroundColor: theme.surface }]}>
          <Pressable 
            style={[styles.tab, activeTab === 'encrypt' && { backgroundColor: theme.primary }]}
            onPress={() => setActiveTab('encrypt')}
          >
            <Text style={[
              styles.tabText, 
              { color: activeTab === 'encrypt' ? '#ffffff' : theme.textSecondary }
            ]}>
              🔒 Encrypt
            </Text>
          </Pressable>
          <Pressable 
            style={[styles.tab, activeTab === 'decrypt' && { backgroundColor: theme.primary }]}
            onPress={() => setActiveTab('decrypt')}
          >
            <Text style={[
              styles.tabText,
              { color: activeTab === 'decrypt' ? '#ffffff' : theme.textSecondary }
            ]}>
              🔓 Decrypt
            </Text>
          </Pressable>
        </View>
      )}

      <ScrollView 
        style={styles.content}
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.scrollContent}
      >
        {activeTab === 'encrypt' ? (
          <Animated.View style={[styles.section, { opacity: fadeAnim }]}>
            <View style={[styles.card, { backgroundColor: theme.surface }]}>
              <Text style={[styles.sectionTitle, { color: theme.text }]}>
                📝 Your Message
              </Text>
      <TextInput
                style={[
                  styles.modernInput, 
                  styles.multilineInput,
                  { 
                    backgroundColor: theme.inputBackground,
                    color: theme.text,
                    borderColor: theme.border
                  }
                ]}
        value={message}
        multiline
        onChangeText={setMessage}
                placeholder="Type your secret message here..."
                placeholderTextColor={theme.textSecondary}
        editable={!isLoading}
      />

              <Text style={[styles.sectionTitle, { color: theme.text }]}>
                🔑 Password
              </Text>
      <TextInput
                style={[
                  styles.modernInput,
                  { 
                    backgroundColor: theme.inputBackground,
                    color: theme.text,
                    borderColor: theme.border
                  }
                ]}
        value={password}
        onChangeText={setPassword}
                placeholder="Enter a strong password"
                placeholderTextColor={theme.textSecondary}
        secureTextEntry
        editable={!isLoading}
      />

      <Pressable 
                style={[
                  styles.modernButton, 
                  styles.primaryButton,
                  { backgroundColor: theme.primary },
                  isLoading && styles.buttonDisabled
                ]} 
        onPress={onEncryptShare}
        disabled={isLoading}
      >
                <Text style={styles.primaryButtonText}>
                  {isLoading ? '🔐 Encrypting...' : '🚀 Encrypt & Share'}
        </Text>
      </Pressable>

              {cipher && (
                <View style={styles.shareSection}>
                  <Text style={[styles.sectionTitle, { color: theme.text }]}>
                    📤 Quick Share
                  </Text>
                  <View style={styles.shareButtons}>
        <Pressable 
                      style={[styles.shareButton, { backgroundColor: '#25D366' }]}
          onPress={openWhatsApp}
                      disabled={isLoading}
        >
                      <Text style={styles.shareButtonText}>WhatsApp</Text>
        </Pressable>
        <Pressable 
                      style={[styles.shareButton, { backgroundColor: '#0088cc' }]}
          onPress={openTelegram}
                      disabled={isLoading}
        >
                      <Text style={styles.shareButtonText}>Telegram</Text>
        </Pressable>
      </View>
                </View>
              )}
            </View>
          </Animated.View>
        ) : (
          <Animated.View style={[styles.section, { opacity: fadeAnim }]}>
            <View style={[styles.card, { backgroundColor: theme.surface }]}>
              <Text style={[styles.sectionTitle, { color: theme.text }]}>
                📥 Encrypted Message
              </Text>
      <TextInput
                style={[
                  styles.modernInput,
                  styles.multilineInput,
                  { 
                    backgroundColor: theme.inputBackground,
                    color: theme.text,
                    borderColor: theme.border
                  }
                ]}
        value={cipher}
        multiline
        onChangeText={setCipher}
                placeholder="Paste encrypted message here..."
                placeholderTextColor={theme.textSecondary}
                editable={!isLoading}
              />

              <Text style={[styles.sectionTitle, { color: theme.text }]}>
                🔑 Password
              </Text>
              <TextInput
                style={[
                  styles.modernInput,
                  { 
                    backgroundColor: theme.inputBackground,
                    color: theme.text,
                    borderColor: theme.border
                  }
                ]}
                value={decryptPassword}
                onChangeText={setDecryptPassword}
                placeholder="Enter password to decrypt"
                placeholderTextColor={theme.textSecondary}
                secureTextEntry
        editable={!isLoading}
      />

              <View style={styles.actionButtons}>
                <Pressable 
                  style={[styles.modernButton, styles.secondaryButton, { borderColor: theme.border }]}
                  onPress={pasteFromClipboard}
                  disabled={isLoading}
                >
                  <Text style={[styles.secondaryButtonText, { color: theme.primary }]}>
                    📋 Paste
                  </Text>
                </Pressable>
                <Pressable 
                  style={[
                    styles.modernButton, 
                    styles.primaryButton,
                    { backgroundColor: theme.primary },
                    isLoading && styles.buttonDisabled
                  ]}
                  onPress={onDecrypt}
                  disabled={isLoading}
                >
                  <Text style={styles.primaryButtonText}>
                    {isLoading ? '🔓 Decrypting...' : '🔓 Decrypt'}
                  </Text>
                </Pressable>
              </View>

              {plainOut && (
                <View style={styles.resultSection}>
                  <Text style={[styles.sectionTitle, { color: theme.text }]}>
                    ✨ Result
                  </Text>
                  <View style={[
                    styles.resultCard,
                    { backgroundColor: theme.inputBackground, borderColor: theme.border },
                    plainOut.startsWith('ERROR:') && styles.errorCard
                  ]}>
                    <Text 
                      selectable 
                      style={[
                        styles.resultText,
                        { color: theme.text },
                        plainOut.startsWith('ERROR:') && styles.errorText
                      ]}
                    >
                      {plainOut || 'Result will appear here...'}
                    </Text>
                  </View>
                  
                  {!plainOut.startsWith('ERROR:') && plainOut && (
                    <Pressable 
                      style={[styles.modernButton, styles.secondaryButton, { borderColor: theme.border }]}
                      onPress={copyPlain}
                    >
                      <Text style={[styles.secondaryButtonText, { color: theme.primary }]}>
                        📋 Copy Result
                      </Text>
                    </Pressable>
                  )}
                </View>
              )}
            </View>
          </Animated.View>
        )}
      </ScrollView>
      
      {/* Bottom Navigation Bar */}
      <View style={[styles.bottomNav, { backgroundColor: theme.surface }]}>
        <Pressable 
          style={[
            styles.bottomNavItem,
            !showCryptoVault && { backgroundColor: theme.primary + '20' }
          ]}
          onPress={() => setShowCryptoVault(false)}
        >
          <Text style={[
            styles.bottomNavIcon,
            { color: !showCryptoVault ? theme.primary : theme.textSecondary }
          ]}>
            💬
          </Text>
          <Text style={[
            styles.bottomNavLabel,
            { color: !showCryptoVault ? theme.primary : theme.textSecondary }
          ]}>
            Messages
          </Text>
        </Pressable>
        
        <Pressable 
          style={[
            styles.bottomNavItem,
            showCryptoVault && { backgroundColor: theme.success + '20' }
          ]}
          onPress={() => setShowCryptoVault(true)}
        >
          <Text style={[
            styles.bottomNavIcon,
            { color: showCryptoVault ? theme.success : theme.textSecondary }
          ]}>
            🔐
          </Text>
          <Text style={[
            styles.bottomNavLabel,
            { color: showCryptoVault ? theme.success : theme.textSecondary }
          ]}>
            Crypto Vault
          </Text>
        </Pressable>
      </View>
    </View>
  );
}

const lightTheme = {
  background: '#f8fafc',
  surface: '#ffffff',
  primary: '#3b82f6',
  secondary: '#64748b',
  text: '#1e293b',
  textSecondary: '#64748b',
  border: '#e2e8f0',
  inputBackground: '#ffffff',
  success: '#10b981',
  error: '#ef4444',
  warning: '#f59e0b',
};

const darkTheme = {
  background: '#0f172a',
  surface: '#1e293b',
  primary: '#3b82f6',
  secondary: '#64748b',
  text: '#f1f5f9',
  textSecondary: '#94a3b8',
  border: '#334155',
  inputBackground: '#334155',
  success: '#10b981',
  error: '#ef4444',
  warning: '#f59e0b',
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    paddingTop: Platform.OS === 'ios' ? 50 : 25,
    paddingHorizontal: 20,
    paddingBottom: 20,
    borderBottomLeftRadius: 24,
    borderBottomRightRadius: 24,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.1,
    shadowRadius: 12,
    elevation: 8,
  },
  headerContent: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  headerButtons: {
    flexDirection: 'row',
    gap: 8,
  },
  navButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  navButtonText: {
    fontSize: 16,
    fontWeight: '700',
  },
  title: {
    fontSize: 28,
    fontWeight: '800',
    letterSpacing: -0.5,
  },
  subtitle: {
    fontSize: 14,
    marginTop: 2,
    opacity: 0.8,
  },
  kdfBadge: {
    fontSize: 10,
    marginTop: 4,
    opacity: 0.9,
    fontWeight: '600',
  },
  themeToggle: {
    width: 44,
    height: 44,
    borderRadius: 22,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  themeToggleText: {
    fontSize: 20,
  },
  tabContainer: {
    flexDirection: 'row',
    margin: 16,
    padding: 4,
    borderRadius: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  tab: {
    flex: 1,
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  tabText: {
    fontSize: 16,
    fontWeight: '600',
  },
  content: {
    flex: 1,
  },
  scrollContent: {
    padding: 16,
  },
  section: {
    marginBottom: 20,
  },
  card: {
    borderRadius: 20,
    padding: 24,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.08,
    shadowRadius: 16,
    elevation: 8,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 16,
    letterSpacing: -0.3,
  },
  modernInput: {
    borderWidth: 2,
    borderRadius: 16,
    paddingHorizontal: 20,
    paddingVertical: 16,
    fontSize: 16,
    marginBottom: 20,
    fontWeight: '500',
  },
  multilineInput: {
    minHeight: 120,
    textAlignVertical: 'top',
  },
  modernButton: {
    borderRadius: 16,
    paddingVertical: 16,
    paddingHorizontal: 24,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 8,
    elevation: 4,
  },
  primaryButton: {
    marginBottom: 16,
  },
  primaryButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.5,
  },
  secondaryButton: {
    backgroundColor: 'transparent',
    borderWidth: 2,
    flex: 1,
    marginRight: 8,
  },
  secondaryButtonText: {
    fontSize: 16,
    fontWeight: '600',
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  shareSection: {
    marginTop: 20,
    paddingTop: 20,
    borderTopWidth: 1,
    borderTopColor: 'rgba(0,0,0,0.1)',
  },
  shareButtons: {
    flexDirection: 'row',
    gap: 12,
  },
  shareButton: {
    flex: 1, 
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center', 
  },
  shareButtonText: {
    color: '#ffffff',
    fontWeight: '600',
    fontSize: 14,
  },
  actionButtons: {
    flexDirection: 'row',
    gap: 12,
  },
  resultSection: {
    marginTop: 24,
    paddingTop: 24,
    borderTopWidth: 1,
    borderTopColor: 'rgba(0,0,0,0.1)',
  },
  resultCard: {
    borderWidth: 2,
    borderRadius: 16,
    padding: 20,
    marginBottom: 16,
    minHeight: 80,
  },
  resultText: {
    fontSize: 16,
    lineHeight: 24,
    fontWeight: '500',
  },
  errorCard: {
    borderColor: '#ef4444',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
  },
  errorText: {
    color: '#ef4444',
  },
  bottomNav: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    paddingVertical: 12,
    paddingBottom: Platform.OS === 'ios' ? 30 : 12,
    borderTopWidth: 1,
    borderTopColor: 'rgba(0,0,0,0.1)',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: -2 },
    shadowOpacity: 0.1,
    shadowRadius: 8,
    elevation: 8,
  },
  bottomNavItem: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 16,
    marginHorizontal: 8,
  },
  bottomNavIcon: {
    fontSize: 24,
    marginBottom: 4,
  },
  bottomNavLabel: {
    fontSize: 12,
    fontWeight: '600',
    textAlign: 'center',
  },
});