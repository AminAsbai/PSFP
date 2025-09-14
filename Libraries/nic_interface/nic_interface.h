#ifndef NIC_INTERFACE_H
#define NIC_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>

// Tamaño máximo de una trama Ethernet (datos crudos)
#define MAX_FRAME_SIZE  1518  // bytes sin jumbo frames (Ethernet II + VLAN)
                              // 1518 = 14 cabecera + 1500 payload + 4 FCS
                              // +4 más si VLAN -> 1522

// Prototipos de tu NIC
bool nic_init(void);
bool nic_receive_raw(uint8_t* buf, uint32_t* len);
void nic_cleanup(void);

#endif // NIC_INTERFACE_H
