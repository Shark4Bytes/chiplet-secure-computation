`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 04/22/2026 05:26:45 PM
// Design Name:
// Module Name: garbler_core
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
//
// Dependencies:
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////

module garbler_core(
    input  wire         clk,
    input  wire         rstn,
    input  wire         start,
    input  wire         generate_cmd,
    input  wire         reset_cmd,
    input  wire [127:0] seed,

    output reg          initialized,
    output reg          busy,
    output reg          done,
    output reg          success,
    output reg          error,
    output reg          data_valid,
    output reg  [31:0]  error_code,

    output reg  [4:0]   bram_addr,
    output reg  [31:0]  bram_din,
    output reg  [3:0]   bram_we,
    output reg          bram_en
);

    localparam ERR_NONE            = 32'd0;
    localparam ERR_ZERO_SEED       = 32'd2;
    localparam ERR_NOT_INITIALIZED = 32'd3;

    localparam ST_UNINITIALIZED = 3'd0;
    localparam ST_READY         = 3'd1;
    localparam ST_GEN_ADVANCE   = 3'd2;
    localparam ST_GEN_WRITE0    = 3'd3;
    localparam ST_GEN_WRITE1    = 3'd4;
    localparam ST_GEN_WRITE2    = 3'd5;
    localparam ST_GEN_WRITE3    = 3'd6;
    localparam ST_RESETTING     = 3'd7;

    reg [2:0]   state;
    reg [127:0] lfsr_state;
    reg [127:0] curr128;
    reg [2:0]   value_idx;      // 0..5
    reg [4:0]   bram_word_idx;  // 0..23

    function [127:0] lfsr_next;
        input [127:0] s;
        begin
            // Placeholder taps. Good enough for bring-up.
            // Replace later with a polynomial/tap set you want.
            lfsr_next = {s[126:0], s[127] ^ s[125] ^ s[100] ^ s[98]};
        end
    endfunction

    always @(posedge clk) begin
        if (!rstn) begin
            state         <= ST_UNINITIALIZED;
            lfsr_state    <= 128'd0;
            curr128       <= 128'd0;
            value_idx     <= 3'd0;
            bram_word_idx <= 5'd0;

            initialized   <= 1'b0;
            busy          <= 1'b0;
            done          <= 1'b0;
            success       <= 1'b0;
            error         <= 1'b0;
            data_valid    <= 1'b0;
            error_code    <= ERR_NONE;

            bram_addr     <= 5'd0;
            bram_din      <= 32'd0;
            bram_we       <= 4'b0000;
            bram_en       <= 1'b0;
        end else begin
            // defaults every cycle
            bram_en <= 1'b0;
            bram_we <= 4'b0000;

            case (state)
                ST_UNINITIALIZED: begin
                    busy <= 1'b0;

                    if (reset_cmd) begin
                        busy          <= 1'b1;
                        done          <= 1'b0;
                        success       <= 1'b0;
                        error         <= 1'b0;
                        error_code    <= ERR_NONE;
                        initialized   <= 1'b0;
                        data_valid    <= 1'b0;
                        bram_word_idx <= 5'd0;
                        state         <= ST_RESETTING;
                    end
                    else if (start) begin
                        done       <= 1'b0;
                        success    <= 1'b0;
                        error      <= 1'b0;
                        error_code <= ERR_NONE;

                        if (seed == 128'd0) begin
                            initialized <= 1'b0;
                            done        <= 1'b1;
                            error       <= 1'b1;
                            error_code  <= ERR_ZERO_SEED;
                        end else begin
                            lfsr_state  <= seed;
                            initialized <= 1'b1;
                            data_valid  <= 1'b0;
                            done        <= 1'b1;
                            success     <= 1'b1;
                            state       <= ST_READY;
                        end
                    end
                    else if (generate_cmd) begin
                        done       <= 1'b1;
                        success    <= 1'b0;
                        error      <= 1'b1;
                        error_code <= ERR_NOT_INITIALIZED;
                    end
                end

                ST_READY: begin
                    if (reset_cmd) begin
                        busy          <= 1'b1;
                        done          <= 1'b0;
                        success       <= 1'b0;
                        error         <= 1'b0;
                        error_code    <= ERR_NONE;
                        initialized   <= 1'b0;
                        data_valid    <= 1'b0;
                        bram_word_idx <= 5'd0;
                        state         <= ST_RESETTING;
                    end
                    else if (start) begin
                        // reinitialize from current seed register value
                        done       <= 1'b0;
                        success    <= 1'b0;
                        error      <= 1'b0;
                        error_code <= ERR_NONE;

                        if (seed == 128'd0) begin
                            initialized <= 1'b0;
                            done        <= 1'b1;
                            error       <= 1'b1;
                            error_code  <= ERR_ZERO_SEED;
                            state       <= ST_UNINITIALIZED;
                        end else begin
                            lfsr_state  <= seed;
                            initialized <= 1'b1;
                            data_valid  <= 1'b0;
                            done        <= 1'b1;
                            success     <= 1'b1;
                        end
                    end
                    else if (generate_cmd) begin
                        busy          <= 1'b1;
                        done          <= 1'b0;
                        success       <= 1'b0;
                        error         <= 1'b0;
                        error_code    <= ERR_NONE;
                        data_valid    <= 1'b0;
                        value_idx     <= 3'd0;
                        bram_word_idx <= 5'd0;
                        state         <= ST_GEN_ADVANCE;
                    end
                end

                ST_GEN_ADVANCE: begin
                    curr128    <= lfsr_next(lfsr_state);
                    lfsr_state <= lfsr_next(lfsr_state);
                    state      <= ST_GEN_WRITE0;
                end

                ST_GEN_WRITE0: begin
                    bram_en       <= 1'b1;
                    bram_we       <= 4'b1111;
                    bram_addr     <= bram_word_idx;
                    bram_din      <= curr128[31:0];
                    bram_word_idx <= bram_word_idx + 1'b1;
                    state         <= ST_GEN_WRITE1;
                end

                ST_GEN_WRITE1: begin
                    bram_en       <= 1'b1;
                    bram_we       <= 4'b1111;
                    bram_addr     <= bram_word_idx;
                    bram_din      <= curr128[63:32];
                    bram_word_idx <= bram_word_idx + 1'b1;
                    state         <= ST_GEN_WRITE2;
                end

                ST_GEN_WRITE2: begin
                    bram_en       <= 1'b1;
                    bram_we       <= 4'b1111;
                    bram_addr     <= bram_word_idx;
                    bram_din      <= curr128[95:64];
                    bram_word_idx <= bram_word_idx + 1'b1;
                    state         <= ST_GEN_WRITE3;
                end

                ST_GEN_WRITE3: begin
                    bram_en   <= 1'b1;
                    bram_we   <= 4'b1111;
                    bram_addr <= bram_word_idx;
                    bram_din  <= curr128[127:96];

                    if (value_idx == 3'd5) begin
                        busy       <= 1'b0;
                        done       <= 1'b1;
                        success    <= 1'b1;
                        error      <= 1'b0;
                        error_code <= ERR_NONE;
                        data_valid <= 1'b1;
                        state      <= ST_READY;
                    end else begin
                        value_idx     <= value_idx + 1'b1;
                        bram_word_idx <= bram_word_idx + 1'b1;
                        state         <= ST_GEN_ADVANCE;
                    end
                end

                ST_RESETTING: begin
                    bram_en   <= 1'b1;
                    bram_we   <= 4'b1111;
                    bram_addr <= bram_word_idx;
                    bram_din  <= 32'd0;

                    if (bram_word_idx == 5'd23) begin
                        lfsr_state    <= 128'd0;
                        curr128       <= 128'd0;
                        value_idx     <= 3'd0;
                        bram_word_idx <= 5'd0;

                        initialized   <= 1'b0;
                        busy          <= 1'b0;
                        done          <= 1'b1;
                        success       <= 1'b1;
                        error         <= 1'b0;
                        data_valid    <= 1'b0;
                        error_code    <= ERR_NONE;

                        state         <= ST_UNINITIALIZED;
                    end else begin
                        bram_word_idx <= bram_word_idx + 1'b1;
                    end
                end

                default: begin
                    state <= ST_UNINITIALIZED;
                end
            endcase
        end
    end

endmodule