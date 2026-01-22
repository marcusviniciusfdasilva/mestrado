`default_nettype none

module clkgen_200KHz (
		input wire clk_100MHz,
		output wire clk_200KHz
		);
		
		reg [7:0]	counter = 8'b0;
		reg clk_reg = 1'b1;
		
		always @(posedge clk_100MHz) begin
			if(counter ==124)begin
				counter <= 8'h00;
				clk_reg<=~clk_reg;
			end
			else
				counter<=counter+1;
		end
		
		assign clk_200KHz = clk_reg;
		
	endmodule 