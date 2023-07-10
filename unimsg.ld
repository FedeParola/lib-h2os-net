/*
 * Some sort of Copyright
 */

__PAGE_SIZE = 0x1000;

SECTIONS
{
	.bss : {
		*(.bss_unprotected)
	}

	.text_unimsg ALIGN(__PAGE_SIZE) : {
		_text_unimsg_start = .;
		*(.text .text.*)
		. = ALIGN(__PAGE_SIZE);
		_text_unimsg_end = .;
	}

	.rodata_unimsg ALIGN(__PAGE_SIZE) : {
		_rodata_unimsg_start = .;
		*(.rodata .rodata.*)
		. = ALIGN(__PAGE_SIZE);
		_rodata_unimsg_end = .;
	}

	.data_unimsg ALIGN(__PAGE_SIZE) : {
		_data_unimsg_start = .;
		*(.data .data.*)
		. = ALIGN(__PAGE_SIZE);
		_data_unimsg_end = .;
	}

	.bss_unimsg ALIGN(__PAGE_SIZE) : {
		_bss_unimsg_start = .;
		*(.bss .bss.*)
		. = ALIGN(__PAGE_SIZE);
		_bss_unimsg_end = .;
	}
}