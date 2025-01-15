# Kernel OTP

## Créer et intéragir avec la vm :

vagrant up

vagrant ssh

sudo su -

## Build et activer le module otp :

cd /otp_module

make

insmod otp.ko

## Désactiver et nettoyer le module otp :

cd /otp_module

make clean

rmmod otp

## Build l'utilitaire :

cd /otp_utilitaire

make

## Nettoyer l'utilitaire :

cd /otp_utilitaire

make fclean

## Utiliser le module otp

### Afficher le dictionaire de mot de passe :

cat /dev/otp_list

### Afficher le code TOTP actuel :

cat /dev/otp_totp

## Utiliser l'utilitaire :

```
Usage: utilitaire
Options:
  --add-password <password>         Add a password to the list
  --set-totp-key <key>              Set the TOTP key\
  --set-totp-interval <interval>    Set the TOTP interval (in seconds)
  --verify-password <password>      Verify a password from the list
  --verify-totp <code>              Verify a TOTP code
  --help                            Show this message
```
