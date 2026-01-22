
`default_nettype none
//`timescale 1ns/1ps 

module chacha_top(
              input    wire       clk_i,         // clock
              input    wire       rst_i,         // reset (synchronous active high)
              input    wire       cyc_i,         // cycle
              input    wire       stb_i,         // strobe
              input    wire [8:0] adr_i,         // address
              input    wire       we_i,          // write enable
              input    wire[31:0] dat_i,         // data input
              input    wire[3:0]  wb_sel,        // data select
              output   wire [31:0] dat_o,         // data output
              output   reg        ack_o,         // normal bus termination
              output   wire       rty_o          // retry output
             );

  // Wishbone interface
	wire wb_acc = cyc_i & stb_i;       // WISHBONE access
	wire wb_wr  = wb_acc & we_i;       // WISHBONE write access


	// ack_o
	always @(posedge clk_i) begin
		if (rst_i)
			ack_o <= 1'b0;
		else
			ack_o <= wb_acc & !ack_o;
	end

//rty_o
  assign rty_o = 1'b0;


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0       = 9'h000;
  localparam ADDR_NAME1       = 9'h004;
  localparam ADDR_VERSION     = 9'h008;

  localparam ADDR_CTRL        = 9'h00c;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;

  localparam ADDR_STATUS      = 9'h010;
  localparam STATUS_READY_BIT = 0;

  localparam ADDR_KEYLEN      = 9'h014;
  localparam KEYLEN_BIT       = 0;
  localparam ADDR_ROUNDS      = 9'h018;
  localparam ROUNDS_HIGH_BIT  = 4;
  localparam ROUNDS_LOW_BIT   = 0;

  ////////////////////////////////////
  localparam ADDR_COUNTER     = 9'h01c;
  //localparam DEFAULT_CTR_INIT = 32'h0;
  ////////////////////////////////////

  localparam ADDR_KEY0        = 9'h0c0;
  localparam ADDR_KEY7        = 9'h0dc;

  localparam ADDR_IV0         = 9'h024;
  localparam ADDR_IV1         = 9'h028;
  ////////////////////////////////////
  localparam ADDR_IV2         = 9'h02c;
  ////////////////////////////////////

  localparam ADDR_DATA_IN0    = 9'h030;
  localparam ADDR_DATA_IN15   = 9'h06c;

  localparam ADDR_DATA_OUT0   = 9'h080;
  localparam ADDR_DATA_OUT15  = 9'h0bc;

  ////////////////////////////////////
  localparam ADDR_CHIFRA_0   = 9'h100;
  localparam ADDR_CHIFRA_15  = 9'h13c;  
  ////////////////////////////////////

  localparam CORE_NAME0       = 32'h63686163; // "chac"
  localparam CORE_NAME1       = 32'h68612020; // "ha  "
  localparam CORE_VERSION     = 32'h302e3830; // "0.80"

  

  localparam datIN_limit      = 12;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg          init_reg;
  reg          init_new;
  reg          next_reg;
  reg          next_new;
  
  reg          CTRL_we;

  reg          keylen_reg;
  reg          keylen_we;

  reg [4 : 0]  rounds_reg;
  reg          rounds_we;

  reg [31 : 0] key_reg [0 : 7];
  reg          key_we;

  reg [31 : 0] iv_reg[0 : 2];
  reg          iv_we;

  reg [31 : 0] data_in_reg [0 : 15];
  reg          data_in_we;

  ///////////////////////////////////
  reg [31:0]  counter_reg;
  reg         counter_we;
  ///////////////////////////////////

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire [255 : 0] core_key;
  wire [95 : 0]  core_iv;
  wire           core_ready;
  wire [511 : 0] core_data_in;
  wire [511 : 0] core_data_out;
  wire           core_data_out_valid;

  ///////////////////////////////////
  wire [511 : 0] core_chifra_out;
  ///////////////////////////////////

  reg [31 : 0]   tmp_read_data;

  //reg [31:0]     data_input;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_key     = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                         key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_iv      = {iv_reg[0], iv_reg[1], iv_reg[2]};

  assign core_data_in = {data_in_reg[00], data_in_reg[01], data_in_reg[02], data_in_reg[03],
                         data_in_reg[04], data_in_reg[05], data_in_reg[06], data_in_reg[07],
                         data_in_reg[08], data_in_reg[09], data_in_reg[10], data_in_reg[11],
                         data_in_reg[12], data_in_reg[13], data_in_reg[14], data_in_reg[15]};

  assign dat_o     = tmp_read_data;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  chacha_core core (
                    .clk(clk_i),
                    .reset_n(rst_i),
                    .init(init_reg),
                    .next(next_reg),
                    .key(core_key),
                    .keylen(keylen_reg),
                    .iv(core_iv),
                    .ctr(counter_reg),
                    .rounds(rounds_reg),
                    .data_in(core_data_in),
                    .ready(core_ready),
                    .data_out(core_data_out),
                    .data_out_valid(core_data_out_valid),
                    .data_chifra(core_chifra_out)
                   );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk_i)
    begin : reg_update
     integer i;
      //if (!rst_i)
      if(rst_i)
        begin
          init_reg   <= 0;
          next_reg   <= 0;
          keylen_reg <= 0;
          rounds_reg <= 5'h0;
          counter_reg <= 32'h0;
          iv_reg[0]  <= 32'h0;
          iv_reg[1]  <= 32'h0;
          iv_reg[2]  <= 32'h0;

          // DATA INPUT////
          //data_input    <= 32'h0;
          ////////////////

          for (i = 0 ; i < 8 ; i = i + 1)
            key_reg[i] <= 32'h0;

          for (i = 0 ; i < 16 ; i = i + 1)
            data_in_reg[i] <= 32'h0;
        end
      else
        begin
          //init_reg <= init_new;
          //next_reg <= next_new;

          // data_input /////////////

          //if (wb_sel [0]) data_input [7:0]   <= dat_i;
          //if (wb_sel [1]) data_input [15:8]  <= dat_i;
          //if (wb_sel [2]) data_input [23:16] <= dat_i;
          //if (wb_sel [3]) data_input [31:24] <= dat_i;

          //////////////////////////
          
          if(CTRL_we)begin
            //init_new <= dat_i[0];
            //next_new <= dat_i[1];
            init_reg <= dat_i[0];
            next_reg <= dat_i[1];
          end
            
          /////////////////////////

          if (keylen_we)
            keylen_reg <= dat_i[KEYLEN_BIT];

          if (rounds_we)
            rounds_reg <= dat_i[ROUNDS_HIGH_BIT : ROUNDS_LOW_BIT];

          //////////////////////////////////////////////////////////
          if (counter_we)
            counter_reg <= dat_i;
          //////////////////////////////////////////////////////////

          if (key_we)
            key_reg[adr_i[4 : 2]] <= dat_i;

          if (iv_we)
            iv_reg[adr_i[3:2]-1] <= dat_i;

          if (data_in_we)
            data_in_reg[(adr_i[7 : 2])-12] <= dat_i;
        end
    end // reg_update


  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  //always @*
  always @(posedge clk_i)
    begin : addr_decoder
      CTRL_we       = 1'h0;
      keylen_we     = 1'h0;
      rounds_we     = 1'h0;
      key_we        = 1'h0;
      iv_we         = 1'h0;
      data_in_we    = 1'h0;
      counter_we    = 1'h0;
      //init_new      = 1'h0;
      //next_new      = 1'h0;
      tmp_read_data = 32'h0;

      if (cyc_i)
        begin
          if (we_i)
            begin
              if (adr_i == ADDR_CTRL)
                begin
                  //init_new = dat_i[CTRL_INIT_BIT];
                  //next_new = dat_i[CTRL_NEXT_BIT];
                  CTRL_we = 1;
                end

              if (adr_i == ADDR_KEYLEN)
                keylen_we = 1;

              if (adr_i == ADDR_ROUNDS)
                rounds_we = 1;

              ////////////////////////////////////////////////
              if (adr_i == ADDR_COUNTER)
                counter_we =1;
              ////////////////////////////////////////////////

              if ((adr_i >= ADDR_KEY0) && (adr_i <= ADDR_KEY7))
                key_we = 1;

              if ((adr_i >= ADDR_IV0) && (adr_i <= ADDR_IV2))
                iv_we = 1;

              if ((adr_i >= ADDR_DATA_IN0) && (adr_i <= ADDR_DATA_IN15))
                data_in_we = 1;

            end // if (we)
          end //(cyc)

          //else
            //begin
              if ((adr_i >= ADDR_KEY0) && (adr_i <= ADDR_KEY7))
                tmp_read_data = key_reg[adr_i[4 : 2]];

              if ((adr_i >= ADDR_DATA_OUT0) && (adr_i <= ADDR_DATA_OUT15))
                tmp_read_data = core_data_out[(15 - (adr_i[5:2])) * 32 +: 32];
                //tmp_read_data = core_data_out[adr_i[6:2]-5'hc];

              ////////////////////////////////////////////////////////////////
              if ((adr_i >= ADDR_CHIFRA_0) && (adr_i <= ADDR_CHIFRA_15))
                tmp_read_data = core_chifra_out[(15 - (adr_i[5:2])) * 32 +: 32];
              ////////////////////////////////////////////////////////////////


              case (adr_i)
                ADDR_NAME0:   tmp_read_data = CORE_NAME0;
                ADDR_NAME1:   tmp_read_data = CORE_NAME1;
                ADDR_VERSION: tmp_read_data = CORE_VERSION;
                ADDR_COUNTER: tmp_read_data = counter_reg;
                ADDR_CTRL:    tmp_read_data = {30'h1, next_reg, init_reg};
                ADDR_STATUS:  tmp_read_data = {30'h0, core_data_out_valid, core_ready};
                ADDR_KEYLEN:  tmp_read_data = {31'h0, keylen_reg};
                ADDR_ROUNDS:  tmp_read_data = {27'h0, rounds_reg};
                ADDR_IV0:     tmp_read_data = iv_reg[0];
                ADDR_IV1:     tmp_read_data = iv_reg[1];
                ADDR_IV2:     tmp_read_data = iv_reg[2];

                default:
                  begin
                  end
              endcase // case (address)
            end
        //end
    //end // addr_decoder
endmodule // chacha
