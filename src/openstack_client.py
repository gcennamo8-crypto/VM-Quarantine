import openstack


def connect_openstack():
    """Crea una connessione autenticata a OpenStack."""
    conn = openstack.connect()
    conn.authorize()
    return conn


def main():
    try:
        conn = connect_openstack()

        print("Connessione OpenStack riuscita!")

        # Verifica Keystone
        print("\n[KEYSTONE]")
        print("Autenticazione riuscita")

        # Verifica Nova
        print("\n[NOVA]")
        for vm in conn.compute.servers():
            print(f"VM: {vm.name} | Stato: {vm.status}")

        # Verifica Neutron
        print("\n[NEUTRON]")
        for sg in conn.network.security_groups():
            print(f"Security Group: {sg.name} | ID: {sg.id}")

    except Exception as error:
        print(f"\nErrore di connessione: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
