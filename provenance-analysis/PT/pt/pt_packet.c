#include "pt_packet.h"

enum pt_packet_kind
pt_get_packet(unsigned char *buffer, unsigned long size, unsigned long *len)
{
	enum pt_packet_kind kind;
	unsigned char first_byte;
	unsigned char second_byte;
	unsigned long cyc_len;
	static unsigned long ipbytes_plus_one[8] = {1, 3, 5, 7, 7, 1, 9, 1};

	if (!buffer || !size) {
		*len = 0;
		return PT_PACKET_NONE;
	}

	first_byte = *buffer;

	if ((first_byte & 0x1) == 0) { // ???????0
		if ((first_byte & 0x2) == 0) { // ??????00
			if (first_byte == 0) {
				kind = PT_PACKET_PAD;
				*len = 1;
			} else {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			}
		} else { // ??????10
			if (first_byte != 0x2) {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			} else {
				if (size < 2) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
					second_byte = *(buffer + 1);
					if ((second_byte & 0x1) == 0) { // ???????0
						if ((second_byte & 0x2) == 0) { // ??????00
							if (second_byte != 0xc8)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_VMCS;
							*len = 7;
						} else { // ??????10
							if (second_byte != 0x82)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_PSB;
							*len = 16;
						}
					} else { // ???????1
						if ((second_byte & 0x10) == 0) { // ???0???1
							if ((second_byte & 0x20) == 0) { // ??00???1
								if ((second_byte & 0x40) == 0) { // ?000???1
									if ((second_byte & 0x80) == 0) { // 0000???1
										if (second_byte != 0x3)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_CBR;
										*len = 4;
									} else { // 1000???1
										if (second_byte != 0x83)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_TRACESTOP;
										*len = 2;
									}
								} else { // ??10???1
									if ((second_byte & 0x80) == 0) { // 0100???1
										if (second_byte != 0x43)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_PIP;
										*len = 8;
									} else { // 1100???1
										if (second_byte != 0xc3)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_MNT;
										*len = 11;
									}
								}
							} else { // ??10???1
								if ((second_byte & 0x80) == 0) { // 0?10???1
									if (second_byte != 0x23)
										return PT_PACKET_ERROR;
									kind = PT_PACKET_PSBEND;
									*len = 2;
								} else { // 1?10???1
									if (second_byte != 0xa3)
										return PT_PACKET_ERROR;
									kind = PT_PACKET_TNTLONG;
									*len = 8;
								}
							}
						} else { // ???1???1
							if ((second_byte & 0x80) == 0) { // 0??1???1
								if (second_byte != 0x73)
									return PT_PACKET_ERROR;
								kind = PT_PACKET_TMA;
								*len = 7;
							} else { // 1??1???1
								if (second_byte != 0xf3)
									return PT_PACKET_ERROR;
								kind = PT_PACKET_OVF;
								*len = 2;
							}
						}
					}
				}
			}
		}
	} else { // ???????1
		if ((first_byte & 0x2) == 0) { // ??????01
			if ((first_byte & 0x4) == 0) { // ?????001
				if ((first_byte & 0x8) == 0) { // ????0001
					if ((first_byte & 0x10) == 0) { // ???00001
						kind = PT_PACKET_TIPPGD;
						*len = ipbytes_plus_one[first_byte>>5];
					} else { // ???10001
						kind = PT_PACKET_TIPPGE;
						*len = ipbytes_plus_one[first_byte>>5];
					}
				} else { // ????1001
					if ((first_byte & 0x40) == 0) { // ?0??1001
						if ((first_byte & 0x80) == 0) { // 00??1001
							if (first_byte != 0x19)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_TSC;
							*len = 8;
						} else { // 10??1001
							if (first_byte != 0x99)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_MODE;
							*len = 2;
						}
					} else { // ?1??1001
						if (first_byte != 0x59)
							return PT_PACKET_ERROR;
						kind = PT_PACKET_MTC;
						*len = 2;
					}
				}
			} else { // ?????101
				if ((first_byte & 0x8) == 0)
					return PT_PACKET_ERROR;
				if ((first_byte & 0x10) == 0) { // ???0?101
					kind = PT_PACKET_TIP;
					*len = ipbytes_plus_one[first_byte>>5];
				} else { // ???1?101
					kind = PT_PACKET_FUP;
					*len = ipbytes_plus_one[first_byte>>5];
				}
			}
		} else { // ??????11
			if ((first_byte & 0x4) == 0) {
				kind = PT_PACKET_CYC;
				*len = 1;
			} else {
				for (cyc_len = 2; cyc_len <= size; cyc_len ++) {
					if (buffer[cyc_len-1] & 0x1) {
						cyc_len ++;
					} else {
						break;
					}
				}
				if (cyc_len > size) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
					kind = PT_PACKET_CYC;
					*len = cyc_len;
				}
			}
		}
	}

	return kind;
}

unsigned long
pt_get_and_update_ip(unsigned char *packet, unsigned int len, unsigned long *last_ip)
{
	unsigned long ip;

	switch (len) {
	case 1:
		ip = 0;
		break;
	case 3:
		ip = ((*last_ip) & 0xffffffffffff0000) |
			*(unsigned short *)(packet+1);
		*last_ip = ip;
		break;
	case 5:
		ip = ((*last_ip) & 0xffffffff00000000) |
			*(unsigned int *)(packet+1);
		*last_ip = ip;
		break;
	case 7:
		if (((*packet) & 0x80) == 0) {
			*(unsigned int *)&ip = *(unsigned int *)(packet+1);
			*((int *)&ip+1) = (int)*(short *)(packet+5);
		} else {
			*(unsigned int *)&ip = *(unsigned int *)(packet+1);
			*((unsigned int *)&ip+1) = ((unsigned int)
					*((unsigned short *)last_ip+3) << 16 |
					(unsigned int)*(unsigned short *)(packet+5));
		}
		*last_ip = ip;
		break;
	case 9:
		ip = *(unsigned long *)(packet+1);
		*last_ip = ip;
		break;
	default:
		ip = 0;
		*last_ip = 0;
		break;
	}

	return ip;
}