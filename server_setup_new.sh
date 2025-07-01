#!/bin/bash

# ==============================================================================
# Script: setup_secure_user.sh
# Descripción: Prepara un servidor Ubuntu/Fedora (compatible con systemd)
#              Creando un nuevo usuario con acceso sudo, configurando claves SSH,
#              y endureciendo la seguridad del SSH.
# Uso: sudo ./setup_secure_user.sh
# ==============================================================================

# ------------------------------------------------------------------------------
# Configuración de Manejo de Errores
# ------------------------------------------------------------------------------
# set -e: Sale inmediatamente si un comando sale con un estado diferente de cero.
# set -u: Trata las variables no establecidas y los parámetros como un error.
# set -o pipefail: Hace que un pipeline falle si un comando falla.
set -euo pipefail

# ------------------------------------------------------------------------------
# Variables Globales
# ------------------------------------------------------------------------------
NEW_USER="ubuntu"
SSH_DIR="/home/$NEW_USER/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
SSHD_CONFIG="/etc/ssh/sshd_config"
TEMP_SUDOERS_FILE="/etc/sudoers.d/90-$NEW_USER-sudo" # Archivo para sudoers

# ------------------------------------------------------------------------------
# Funciones
# ------------------------------------------------------------------------------

# Función para verificar si el usuario es root
check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Por favor, ejecute este script como root (sudo)."
    exit 1
  fi
}

# Función para agregar un nuevo usuario
add_new_user() {
  if id "$NEW_USER" &>/dev/null; then
    echo "INFO: El usuario '$NEW_USER' ya existe. Omitiendo creación."
  else
    echo "INFO: Creando usuario '$NEW_USER'..."
    # --disabled-password: No le asigna una contraseña inicial (se usará SSH).
    # --gecos "": No pide información adicional del usuario.
    # --shell /bin/bash: Asigna bash como shell por defecto.
    if adduser --disabled-password --gecos "" --shell /bin/bash "$NEW_USER"; then
      echo "EXITO: Usuario '$NEW_USER' creado."
    else
      echo "ERROR: Falló la creación del usuario '$NEW_USER'."
      exit 1
    fi

    # Otorgar acceso sudo al nuevo usuario de forma segura
    # Esto es mejor que modificar directamente /etc/sudoers
    if [ ! -f "$TEMP_SUDOERS_FILE" ]; then
      echo "INFO: Otorgando acceso sudo al usuario '$NEW_USER'..."
      echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee "$TEMP_SUDOERS_FILE" > /dev/null
      sudo chmod 0440 "$TEMP_SUDOERS_FILE"
      echo "EXITO: Acceso sudo otorgado al usuario '$NEW_USER' sin contraseña para 'sudo'."
      echo "ADVERTENCIA: Considere cambiar 'NOPASSWD:ALL' si desea que el usuario ingrese su contraseña para 'sudo'."
    else
      echo "INFO: El archivo sudoers para '$NEW_USER' ya existe."
    fi
  fi
}

# Función para configurar el directorio .ssh y authorized_keys
setup_ssh_keys() {
  echo "INFO: Verificando/Configurando directorio SSH para '$NEW_USER'..."

  # Crear directorio .ssh si no existe y asegurar permisos/propiedad
  if [ ! -d "$SSH_DIR" ]; then
    if mkdir -p "$SSH_DIR"; then
      echo "EXITO: Directorio '$SSH_DIR' creado."
    else
      echo "ERROR: Falló la creación del directorio '$SSH_DIR'."
      exit 1
    fi
  else
    echo "INFO: Directorio '$SSH_DIR' ya existe."
  fi

  # Asegurar permisos correctos para el directorio .ssh
  if chmod 700 "$SSH_DIR"; then
    echo "EXITO: Permisos 700 establecidos para '$SSH_DIR'."
  else
    echo "ERROR: Falló al establecer permisos para '$SSH_DIR'."
    exit 1
  fi

  # Asegurar propiedad correcta para el directorio .ssh
  if chown -R "$NEW_USER":"$NEW_USER" "$SSH_DIR"; then
    echo "EXITO: Propiedad de '$SSH_DIR' establecida a '$NEW_USER:$NEW_USER'."
  else
    echo "ERROR: Falló al establecer propiedad para '$SSH_DIR'."
    exit 1
  fi

  # Crear archivo authorized_keys si no existe y asegurar permisos/propiedad
  if [ ! -f "$AUTHORIZED_KEYS" ]; then
    if touch "$AUTHORIZED_KEYS"; then
      echo "EXITO: Archivo '$AUTHORIZED_KEYS' creado."
    else
      echo "ERROR: Falló la creación del archivo '$AUTHORIZED_KEYS'."
      exit 1
    fi
  else
    echo "INFO: Archivo '$AUTHORIZED_KEYS' ya existe."
  fi

  # Asegurar permisos correctos para authorized_keys
  if chmod 600 "$AUTHORIZED_KEYS"; then
    echo "EXITO: Permisos 600 establecidos para '$AUTHORIZED_KEYS'."
  else
    echo "ERROR: Falló al establecer permisos para '$AUTHORIZED_KEYS'."
    exit 1
  fi

  # Asegurar propiedad correcta para authorized_keys
  if chown "$NEW_USER":"$NEW_USER" "$AUTHORIZED_KEYS"; then
    echo "EXITO: Propiedad de '$AUTHORIZED_KEYS' establecida a '$NEW_USER:$NEW_USER'."
  else
    echo "ERROR: Falló al establecer propiedad para '$AUTHORIZED_KEYS'."
    exit 1
  fi

  echo "INFO: Ahora, por favor, pegue las claves públicas SSH que desea agregar."
  echo "INFO: Cada clave debe estar en una nueva línea."
  echo "INFO: Cuando haya terminado, presione Enter, luego Ctrl+D para guardar y continuar."

  # Leer las claves de SSH del usuario de forma segura
  # Usar un array para manejar múltiples líneas de forma más robusta
  declare -a USER_KEYS_ARRAY
  while IFS= read -r line; do
      USER_KEYS_ARRAY+=("$line")
  done

  if [ "${#USER_KEYS_ARRAY[@]}" -eq 0 ]; then
    echo "ADVERTENCIA: No se proporcionaron claves SSH. El usuario no podrá iniciar sesión por SSH."
  fi

  for KEY in "${USER_KEYS_ARRAY[@]}"; do
    if [ -n "$KEY" ]; then # Asegurarse de que la línea no esté vacía
      # -q: modo silencioso, -F: cadena fija, -x: línea completa
      if ! grep -qxF -- "$KEY" "$AUTHORIZED_KEYS"; then # -- para manejar claves con guiones
        echo "$KEY" >> "$AUTHORIZED_KEYS"
        echo "EXITO: Clave agregada a '$AUTHORIZED_KEYS'."
      else
        echo "INFO: La clave ya existe en '$AUTHORIZED_KEYS'. Omitiendo."
      fi
    fi
  done

  echo "INFO: Claves SSH procesadas para '$NEW_USER'."
}

# Función para endurecer la configuración de SSH
harden_ssh_config() {
  echo "INFO: Endureciendo la configuración de SSH ($SSHD_CONFIG)..."

  # Array de configuraciones a cambiar
  declare -a SSH_CHANGES=(
    "PermitRootLogin no"
    "PasswordAuthentication no"
    "ChallengeResponseAuthentication no"
    "UsePAM no"
    "X11Forwarding no"
    "PermitEmptyPasswords no"
  )

  # Para cada configuración, buscar y reemplazar o agregar
  for SETTING in "${SSH_CHANGES[@]}"; do
    KEY=$(echo "$SETTING" | cut -d' ' -f1) # Extrae la clave (e.g., PermitRootLogin)
    VALUE=$(echo "$SETTING" | cut -d' ' -f2) # Extrae el valor (e.g., no)

    if grep -q "^#\?${KEY}[[:space:]]*" "$SSHD_CONFIG"; then # Busca la línea existente
      echo "INFO: Actualizando '$KEY' a '$VALUE'..."
      # Usar un patrón más robusto para reemplazar líneas existentes
      sudo sed -i -E "s/^#?${KEY}[[:space:]]+.*$/${KEY} ${VALUE}/" "$SSHD_CONFIG"
    else
      echo "INFO: '$KEY' no encontrado. Agregando '$SETTING' al final del archivo..."
      echo "$SETTING" | sudo tee -a "$SSHD_CONFIG" > /dev/null
    fi
  done

  # Asegurarse de que el servicio SSH esté configurado para iniciarse al arrancar (habilitado)
  if ! systemctl is-enabled --quiet ssh; then
    echo "INFO: Habilitando el servicio SSH para que inicie al arranque..."
    sudo systemctl enable ssh || echo "ADVERTENCIA: No se pudo habilitar el servicio SSH para el arranque."
  else
    echo "INFO: El servicio SSH ya está habilitado para iniciar al arranque."
  fi

  # Reiniciar el servicio SSH
  echo "ADVERTENCIA: Reiniciar el servicio SSH puede desconectar las sesiones activas."
  if sudo systemctl restart ssh; then
    echo "EXITO: Servicio SSH reiniciado."
  else
    echo "ERROR: Falló al reiniciar el servicio SSH. Por favor, revise los logs."
    exit 1
  fi
}

# Función para imprimir el mensaje final
print_final_message() {
  cat <<"EOF"


             .------~---------~-----.
             | .------------------. |
             | |                  | |
             | |   .'''.  .'''.   | |
             | |   :    ''    :   | |
             | |   :          :   | |
             | |    '.      .'    | |
             | |      '.  .'      | |
             | |        ''        | |
             | `------------------' |
             `.____________________.'
               `-------.  .-------'
        .--.      ____.'  `.____
      .-~--~-----~--------------~----.
      |     .---------.|.--------.|()|
      |     `---------'|`-o-=----'|  |
      |-*-*------------| *--  (==)|  |
      |                |          |  |
      `------------------------------'

¡Felicidades!
Tu servidor ha sido configurado y endurecido.
Usuario '$NEW_USER' creado con acceso sudo y SSH.
¡Tu servidor está listo para el próximo script!
EOF
}

# ------------------------------------------------------------------------------
# Ejecución Principal del Script
# ------------------------------------------------------------------------------

echo "INICIO: Ejecutando script de configuración segura de servidor."

check_root
add_new_user
setup_ssh_keys
harden_ssh_config
print_final_message

echo "FIN: Script de configuración completado con éxito."
