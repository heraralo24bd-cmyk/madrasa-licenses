# Revocation List SPEC (v1) — Madrasa Manager অনলাইন লাইসেন্স বাতিল

এই ফাইলটি `revocations.json`-এর ফরম্যাট নথিভুক্ত করে, যাতে ওয়েব "লাইসেন্স মেশিন"
(admin/) ও ডেস্কটপ অ্যাপ (Rust) একইভাবে তৈরি/যাচাই করতে পারে।

## ফাইল অবস্থান
`https://<owner>.github.io/madrasa-licenses/revocations.json`
(রিপো: `madrasa-licenses`, রুটে)

## JSON ফরম্যাট
```json
{"v":1,"issued_at":1760000000,"revoked":["<license_id_32hex>", "..."],"signature":"<base64url_nopad>"}
```
- `v`: ফরম্যাট সংস্করণ (১)
- `issued_at`: ইউনিক্স সেকেন্ড (কখন এই তালিকা স্বাক্ষরিত হলো)
- `revoked`: বাতিল license_id-এর তালিকা — **lexicographic সর্টেড**, ডুপ্লিকেটমুক্ত
- `signature`: নিচের পদ্ধতিতে তৈরি Ed25519 ডিটাচড স্বাক্ষর, base64url (no pad)

## স্বাক্ষর পদ্ধতি
1. স্বাক্ষর-পেলোড JSON (স্পেস ছাড়া, ফিল্ড অর্ডার **v, issued_at, revoked**):
   `{"v":1,"issued_at":<N>,"revoked":[<sorted ids>]}`
2. UTF-8 বাইটের উপর Ed25519 ডিটাচড সাইন (RFC 8032, deterministic)
3. চাবি: মালিকের বিদ্যমান Ed25519 কী-জোড়া (Owner-Key.json-এর `secret_seed`;
   পাবলিক কী `licensing-client.json`-এ এমবেডেড — একই কী লাইসেন্স স্বাক্ষরেও ব্যবহৃত)

## ডেস্কটপ অ্যাপের যাচাই নিয়ম (বাস্তবায়ন নির্দেশিকা)
1. `revocation_url` থেকে ফাইল আনুন (startup + প্রতি কয়েক ঘণ্টায় ব্যাকগ্রাউন্ডে)
2. `signature` যাচাই করুন এমবেডেড পাবলিক কী দিয়ে — **অবৈধ হলে পুরো ফাইল বাতিল**
   (আগের জানা-ভালো তালিকাই বহাল রাখুন)
3. `issued_at` > আগে সংরক্ষিত `issued_at` হতে হবে (replay সুরক্ষা);
   সমান/ছোট হলে উপেক্ষা করুন
4. নিজের `license_id` তালিকায় থাকলে → লাইসেন্স বাতিল অবস্থায় নিন
   (অ্যাপ লক / পুনঃসক্রিয়করণ চাইবে)
5. ইন্টারনেট না থাকলে → আগের মতো অফলাইনেই চলবে (বাতিল চেক হবে না)

## লাইসেন্স কী ফরম্যাট (রেফারেন্স — Rust `licensing.rs`/`owner_generator.rs`-এর সাথে হুবহু)
- কী: `MM1.<base64url_nopad(payload)>.<base64url_nopad(signature)>`
- পেলোড JSON ফিল্ড অর্ডার: `v, product, license_id, customer_name, device_id, issued_at, expires_at`
  (`expires_at`: আজীবন হলে `null`)
- `product` = `"madrasa-manager"`, `device_id` = ৬৪ hex (ছোট হাতের, `MM-PC-` ছাড়া)
