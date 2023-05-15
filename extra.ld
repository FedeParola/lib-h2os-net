SECTIONS
{
	.text_h2os : {
		PROVIDE(_text_h2os_start = .);
		*(.text .text.*)
		PROVIDE(_text_h2os_end = .);
	}
}
INSERT BEFORE .text;

SECTIONS
{
	.rodata_h2os : {
		PROVIDE(_rodata_h2os_start = .);
		*(.rodata .rodata.*)
		PROVIDE(_rodata_h2os_end = .);
	}
}
INSERT BEFORE .rodata;

SECTIONS
{
	.data_h2os : {
		PROVIDE(_data_h2os_start = .);
		*(.data .data.*)
		PROVIDE(_data_h2os_end = .);
	}
}
INSERT BEFORE .data;

SECTIONS
{
	.bss_h2os : {
		PROVIDE(_bss_h2os_start = .);
		*(.bss .bss.*)
		PROVIDE(_bss_h2os_end = .);
	}
}
INSERT BEFORE .bss;