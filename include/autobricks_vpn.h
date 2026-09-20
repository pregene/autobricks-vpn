#ifndef AUTOBRICKS_VPN_H
#define AUTOBRICKS_VPN_H

#ifdef __cplusplus
extern "C" {
#endif

/* config_path is required and must not be NULL or empty.
 * Returns 0 on normal shutdown and a non-zero status on error. */
int autobricks_vpn_server_run(const char *config_path);
int autobricks_vpn_client_run(const char *config_path);
/* user and password are both required and must not be NULL. */
int autobricks_vpn_client_run_with_login(const char *config_path, const char *user, const char *password);

#ifdef __cplusplus
}
#endif

#endif
