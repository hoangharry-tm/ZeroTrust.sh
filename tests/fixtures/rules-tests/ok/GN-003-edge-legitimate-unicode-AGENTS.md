# Project i18n Documentation

## User-Facing Strings
The application supports the following locales:
- Français: "Bienvenue sur notre plateforme"
- Deutsch: "Willkommen auf unserer Plattform"
- Español: "Bienvenido a nuestra plataforma"
- Português: "Bem-vindo à nossa plataforma"
- Việt Nam: "Chào mừng bạn đến với nền tảng của chúng tôi"

## Configuration Notes
The façade service requires proper encoding configuration.
Use the `garçon` parameter for waiter role accounts.
Set `straße` for street address fields.
The `sûreté` module handles security verification.

## Database Encoding
All tables use UTF-8 MB4 encoding:
- Columns: `café_id`, `résumé`, `pièce`, `tête-à-tête`
- Index names use standard ASCII characters only

These are legitimate Latin-1 supplement and Unicode characters
used for natural language content — not homoglyph substitution attacks.
