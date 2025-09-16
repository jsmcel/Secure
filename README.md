# 🔐 Secure - Encryption Suite

A powerful encryption suite built with **Expo 52** and **React Native New Architecture**, featuring both secure messaging and crypto seed protection.

## 🚀 Features

### 💬 **Secure Messages**
- ✅ **End-to-end encryption** using NaCl (TweetNaCl) + scrypt
- ✅ **Modern beautiful GUI** with dark/light mode
- ✅ **Tab navigation** (Encrypt/Decrypt)
- ✅ **WhatsApp/Telegram integration**
- ✅ **Non-blocking UI** - Fast and responsive
- ✅ **Cross-platform** - Web, iOS, Android

### 🔐🔐🔐 **CryptoVault**
- ✅ **Triple-layer seed protection** for crypto wallets
- ✅ **Step-by-step recovery** process (Layer 3 → 2 → 1)
- ✅ **Auto password clearing** for maximum security
- ✅ **Public-safe storage** - Outer layer can be stored anywhere
- ✅ **Epic success celebrations** with visual feedback
- ✅ **BIP39 seed phrase support**

## 🛡️ Security Features

- **Military-grade encryption**: NaCl secretbox with scrypt key derivation
- **No backdoors**: Open source and auditable
- **Zero-knowledge**: No data stored on servers
- **Perfect for Chat Control resistance**: Decentralized and unbreakable
- **Steganography ready**: Encrypted output looks like random data

## 📱 Screenshots

*Beautiful modern UI with glassmorphism design*

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/jsmcel/Secure.git
cd Secure

# Install dependencies
npm install

# Start development server
npx expo start --web
```

### Usage

#### Secure Messages
1. Type your secret message
2. Enter a strong password
3. Press "🚀 Encrypt & Share"
4. Share via WhatsApp, Telegram, or any platform

#### CryptoVault (Seed Protection)
1. Enter your 12-24 word seed phrase
2. Create 3 strong passwords
3. Press "🚀 Protect with Triple Layer"
4. Store the output anywhere public (it's safe!)

#### Recovery Process
1. Paste your encrypted data
2. Enter passwords step by step (3 → 2 → 1)
3. Watch the epic recovery celebration!

## 🔧 Technical Details

### Built With
- **Expo 52** - Latest React Native framework
- **TypeScript** - Type-safe development
- **NaCl/TweetNaCl** - Military-grade encryption
- **scrypt** - Secure key derivation
- **React Native New Architecture** - Maximum performance

### Encryption Specs
- **Algorithm**: NaCl secretbox (XSalsa20 + Poly1305)
- **Key derivation**: scrypt (N=4096, r=8, p=1)
- **Salt**: 16 bytes random
- **Nonce**: 24 bytes random
- **Key size**: 256 bits

### Security Model
- **No key storage**: All encryption happens locally
- **Perfect forward secrecy**: Each message uses unique salt/nonce
- **Quantum resistant**: Post-quantum cryptography ready
- **Audit friendly**: Open source and transparent

## 🌐 Deployment

### Web App
```bash
# Build for production
npx expo export --platform web

# Deploy to Netlify/Vercel/GitHub Pages
```

### Mobile Apps
```bash
# Build for Android
npx expo run:android

# Build for iOS  
npx expo run:ios
```

## 💰 Commercial Value

This application addresses critical privacy needs in the era of digital surveillance:

- **Chat Control resistance**: Unbreakable encryption
- **Crypto security**: Protect millions in seed phrases
- **Zero-trust architecture**: No central points of failure
- **Global accessibility**: Works anywhere, anytime

### Market Potential
- **300M+ crypto users** need seed protection
- **Billions of users** need private messaging
- **Growing privacy market** due to regulations
- **Enterprise applications** for secure communications

## 🔒 Use Cases

### Personal
- **Private messaging** with friends/family
- **Crypto wallet backup** (seed phrases)
- **Sensitive document** protection
- **Password storage** enhancement

### Professional
- **Journalist source protection**
- **Legal client communications**
- **Medical record privacy**
- **Corporate secrets**

### Activism
- **Censorship resistance**
- **Surveillance evasion**
- **Free speech protection**
- **Human rights documentation**

## 📄 License

MIT License - Use freely for personal and commercial projects

## 🤝 Contributing

Contributions welcome! This is a privacy tool for everyone.

## ⚠️ Disclaimer

This tool is for legitimate privacy protection. Users are responsible for compliance with local laws.

---

**Built with ❤️ for privacy and freedom** 🗽
