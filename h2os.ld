/*
 * Some sort of Copyright
 */

__PAGE_SIZE = 0x1000;

SECTIONS
{
	.text_h2os ALIGN(__PAGE_SIZE) : {
		_text_h2os_start = .;
		*(.text .text.*)
		. = ALIGN(__PAGE_SIZE);
		_text_h2os_end = .;
	}

	.rodata_h2os ALIGN(__PAGE_SIZE) : {
		_rodata_h2os_start = .;
		*(.rodata .rodata.*)
		. = ALIGN(__PAGE_SIZE);
		_rodata_h2os_end = .;
		. = ALIGN(__PAGE_SIZE);
		_babumba = .;
	}

	.data_h2os ALIGN(__PAGE_SIZE) : {
		_data_h2os_start = .;
		*(.data .data.*)
		. = ALIGN(__PAGE_SIZE);
		_data_h2os_end = .;
	}

	.bss_h2os ALIGN(__PAGE_SIZE) : {
		_bss_h2os_start = .;
		*(.bss .bss.*)
		. = ALIGN(__PAGE_SIZE);
		_bss_h2os_end = .;
	}
}