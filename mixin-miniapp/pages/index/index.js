const crypto = require('../../utils/crypto.js');

Page({
  data: {
    mode: 'encrypt',
    key: '',
    showKey: false,
    saveKey: false,
    plainText: '',
    cipherText: '',
    cipherOutput: '',
    plainOutput: '',
    encrypting: false,
    decrypting: false
  },

  onLoad() {
    const saved = wx.getStorageSync('mixin_save');
    if (saved) {
      const key = wx.getStorageSync('mixin_key') || '';
      this.setData({ saveKey: true, key });
    }
  },

  // === Key management ===
  onKeyInput(e) {
    this.setData({ key: e.detail.value });
    if (this.data.saveKey) {
      wx.setStorageSync('mixin_key', e.detail.value);
    }
  },

  toggleKey() {
    this.setData({ showKey: !this.data.showKey });
  },

  generateKey() {
    const key = crypto.generateRandomKey();
    this.setData({ key, showKey: true });
    if (this.data.saveKey) {
      wx.setStorageSync('mixin_key', key);
    }
    wx.showToast({ title: '已生成，请线下告知对方', icon: 'none' });
  },

  toggleSaveKey() {
    const saveKey = !this.data.saveKey;
    this.setData({ saveKey });
    if (saveKey) {
      wx.setStorageSync('mixin_save', '1');
      wx.setStorageSync('mixin_key', this.data.key);
    } else {
      wx.removeStorageSync('mixin_save');
      wx.removeStorageSync('mixin_key');
    }
  },

  // === Tab switching ===
  switchToEncrypt() {
    this.setData({ mode: 'encrypt' });
  },

  switchToDecrypt() {
    this.setData({ mode: 'decrypt' });
  },

  // === Encrypt ===
  onPlainInput(e) {
    this.setData({ plainText: e.detail.value });
  },

  doEncrypt() {
    const { key, plainText } = this.data;
    if (!key) return wx.showToast({ title: '请先输入密钥', icon: 'none' });
    if (!plainText) return wx.showToast({ title: '请输入要加密的消息', icon: 'none' });
    if (this.data.encrypting) return;

    this.setData({ encrypting: true });

    // Use setTimeout to let UI update first (PBKDF2 is CPU-heavy)
    setTimeout(() => {
      try {
        const result = crypto.encrypt(plainText, key);
        this.setData({ cipherOutput: result, encrypting: false });

        // Auto copy to clipboard
        wx.setClipboardData({
          data: result,
          success: () => {
            wx.showToast({ title: '加密成功，已复制', icon: 'success' });
          }
        });
      } catch (e) {
        this.setData({ encrypting: false });
        wx.showToast({ title: '加密失败: ' + e.message, icon: 'none' });
      }
    }, 50);
  },

  // === Decrypt ===
  onCipherInput(e) {
    const value = e.detail.value;
    this.setData({ cipherText: value });

    // Auto decrypt after input settles
    if (this._decryptTimer) clearTimeout(this._decryptTimer);
    this._decryptTimer = setTimeout(() => {
      if (value.trim()) this.doDecrypt();
    }, 500);
  },

  doDecrypt() {
    const { key, cipherText } = this.data;
    if (!key) return wx.showToast({ title: '请先输入密钥', icon: 'none' });
    if (!cipherText) return wx.showToast({ title: '请粘贴加密消息', icon: 'none' });
    if (this.data.decrypting) return;

    this.setData({ decrypting: true });

    setTimeout(() => {
      try {
        const result = crypto.decrypt(cipherText, key);
        this.setData({ plainOutput: result, decrypting: false });
        wx.showToast({ title: '解密成功', icon: 'success' });
      } catch (e) {
        this.setData({ decrypting: false, plainOutput: '' });
        wx.showToast({ title: '密钥错误或数据无效', icon: 'none' });
      }
    }, 50);
  },

  // === Copy ===
  copyCipher() {
    if (!this.data.cipherOutput) return;
    wx.setClipboardData({
      data: this.data.cipherOutput,
      success: () => wx.showToast({ title: '已复制', icon: 'success' })
    });
  },

  copyPlain() {
    if (!this.data.plainOutput) return;
    wx.setClipboardData({
      data: this.data.plainOutput,
      success: () => wx.showToast({ title: '已复制', icon: 'success' })
    });
  }
});
