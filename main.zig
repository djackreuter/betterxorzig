const std = @import("std");

pub fn main() !void {
    const fileBuffer: []const u8 = @embedFile("shellcode.bin");

    var buffer: [fileBuffer.len]u8 = undefined;

    std.debug.print("[+] file length: {}\n", .{fileBuffer.len});

    std.debug.print("[+] Running XOR\n", .{});
    try singleKeyXOR(fileBuffer, &buffer);

    std.debug.print("-- Clearing buffer\n", .{});
    buffer = [_]u8{0x00} ** fileBuffer.len;

    std.debug.print("[+] Running rotating key XOR\n", .{});
    try rotatingKeyXOR(fileBuffer, &buffer);

    std.debug.print("-- Clearing buffer\n", .{});
    buffer = [_]u8{0x00} ** fileBuffer.len;

    std.debug.print("[+] Running rotating key skipping null bytes XOR\n", .{});
    try rotatingKeySkipNullXOR(fileBuffer, &buffer);

    std.debug.print("[+] Decrypting\n", .{});
    try rotatingKeySkipNullDecrypt();
}

pub fn singleKeyXOR(fileBuffer: []const u8, buffer: []u8) !void {
    const key: u8 = 'A';

    for (fileBuffer, 0..fileBuffer.len) |char, i| {
        buffer[i] = char ^ key;
    }

    const file = try std.fs.cwd().createFile("normal_xor.bin", .{ .read = true });

    defer file.close();

    try file.writeAll(buffer);
}

pub fn rotatingKeyXOR(fileBuffer: []const u8, buffer: []u8) !void {
    const key: []const u8 = "testing";

    var j: usize = 0;
    for (fileBuffer, 0..fileBuffer.len) |char, i| {
        if (j == key.len) {
            j = 0;
        }
        buffer[i] = char ^ key[j];
        j += 1;
    }

    const file = try std.fs.cwd().createFile("rotatingkey_xor.bin", .{ .read = true });

    defer file.close();

    try file.writeAll(buffer);
}

pub fn rotatingKeySkipNullXOR(fileBuffer: []const u8, buffer: []u8) !void {
    const key: []const u8 = "testing";

    const ArrayList = std.ArrayList;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var indicies = ArrayList(usize).init(allocator);

    defer indicies.deinit();

    var j: usize = 0;
    for (fileBuffer, 0..fileBuffer.len) |char, i| {
        if (char == 0x00) {
            try indicies.append(i);
            continue;
        }
        if (j == key.len) {
            j = 0;
        }
        buffer[i] = char ^ key[j];
        j += 1;
    }

    std.debug.print("Indicies: {d}\n", .{indicies.items});
    std.debug.print("Indicies length: {d} \n", .{indicies.items.len});

    const file = try std.fs.cwd().createFile("rotatingkey_skip_nullbytes_xor.bin", .{ .read = true });

    defer file.close();

    try file.writeAll(buffer);
}

pub fn rotatingKeySkipNullDecrypt() !void {
    const fileBuffer: []const u8 = @embedFile("rotatingkey_skip_nullbytes_xor.bin");

    const key = "testing";
    const indicies = [_]usize{ 7, 8, 9, 80, 81, 82, 206, 207, 208, 209, 210, 211, 212, 218, 219, 260, 295 };

    var dec_buffer: [fileBuffer.len]u8 = undefined;

    var j: usize = 0;
    var current_index: [*]const usize = &indicies;

    for (fileBuffer, 0..fileBuffer.len) |char, i| {
        if (current_index[0] == i) {
            current_index += 1;
            continue;
        }
        if (j == key.len) {
            j = 0;
        }
        dec_buffer[i] = char ^ key[j];
        j += 1;
    }

    const file = try std.fs.cwd().createFile("decrypted.bin", .{ .read = true });

    defer file.close();

    try file.writeAll(&dec_buffer);
}
