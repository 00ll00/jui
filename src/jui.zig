const std = @import("std");
const builtin = @import("builtin");

pub const bindings = @import("bindings.zig");
pub const descriptors = @import("descriptors.zig");
pub const Reflector = @import("Reflector.zig");
const types = @import("types.zig");

// We support Zig 0.9.1 (old stable), 0.10.0 (current stable) and 0.11.0-dev (latest master).
// We also support both stage1 and stage2 compilers.
// This can be simplified once we drop support for Zig 0.9.1 and stage1:
pub const is_zig_9_1 = builtin.zig_version.major >= 0 and builtin.zig_version.minor == 9;
pub const is_zig_master = builtin.zig_version.major >= 0 and builtin.zig_version.minor >= 11;
pub const is_stage2 = @hasDecl(builtin, "zig_backend") and builtin.zig_backend != .stage1;

// pub usingnamespace types;
pub const va_list = types.va_list;
pub const JNICALL = types.JNICALL;
pub const jint = types.jint;
pub const jlong = types.jlong;
pub const jbyte = types.jbyte;
pub const jboolean = types.jboolean;
pub const jchar = types.jchar;
pub const jshort = types.jshort;
pub const jfloat = types.jfloat;
pub const jdouble = types.jdouble;
pub const jsize = types.jsize;
pub const jobject = types.jobject;
pub const jclass = types.jclass;
pub const jthrowable = types.jthrowable;
pub const jstring = types.jstring;
pub const jarray = types.jarray;
pub const jbooleanArray = types.jbooleanArray;
pub const jbyteArray = types.jbyteArray;
pub const jcharArray = types.jcharArray;
pub const jshortArray = types.jshortArray;
pub const jintArray = types.jintArray;
pub const jlongArray = types.jlongArray;
pub const jfloatArray = types.jfloatArray;
pub const jdoubleArray = types.jdoubleArray;
pub const jobjectArray = types.jobjectArray;
pub const jweak = types.jweak;
pub const NativeType = types.NativeType;
pub const MapNativeType = types.MapNativeType;
pub const MapArrayType = types.MapArrayType;
pub const jvalue = types.jvalue;
pub const toJValue = types.toJValue;
pub const jfieldID = types.jfieldID;
pub const jmethodID = types.jmethodID;
pub const ObjectReferenceKind = types.ObjectReferenceKind;
pub const JNIFailureError = types.JNIFailureError;
pub const JNINativeMethod = types.JNINativeMethod;
pub const JNIVersion = types.JNIVersion;
pub const JNIEnv = types.JNIEnv;
pub const getClassNameOfObject = types.getClassNameOfObject;
pub const getJNIVersion = types.getJNIVersion;
pub const getJavaVM = types.getJavaVM;
pub const DefineClassError = types.DefineClassError;
pub const defineClass = types.defineClass;
pub const FindClassError = types.FindClassError;
pub const findClass = types.findClass;
pub const getSuperclass = types.getSuperclass;
pub const isAssignableFrom = types.isAssignableFrom;
pub const getModule = types.getModule;
pub const throw = types.throw;
pub const throwNew = types.throwNew;
pub const throwGeneric = types.throwGeneric;
pub const getPendingException = types.getPendingException;
pub const describeException = types.describeException;
pub const clearPendingException = types.clearPendingException;
pub const fatalError = types.fatalError;
pub const hasPendingException = types.hasPendingException;
pub const NewReferenceError = types.NewReferenceError;
pub const newReference = types.newReference;
pub const deleteReference = types.deleteReference;
pub const ensureLocalCapacity = types.ensureLocalCapacity;
pub const pushLocalFrame = types.pushLocalFrame;
pub const popLocalFrame = types.popLocalFrame;
pub const AllocObjectError = types.AllocObjectError;
pub const allocObject = types.allocObject;
pub const NewObjectError = types.NewObjectError;
pub const newObject = types.newObject;
pub const getObjectClass = types.getObjectClass;
pub const getObjectReferenceKind = types.getObjectReferenceKind;
pub const isInstanceOf = types.isInstanceOf;
pub const isSameObject = types.isSameObject;
pub const GetFieldIdError = types.GetFieldIdError;
pub const getFieldId = types.getFieldId;
pub const getField = types.getField;
pub const setField = types.setField;
pub const GetMethodIdError = types.GetMethodIdError;
pub const getMethodId = types.getMethodId;
pub const CallMethodError = types.CallMethodError;
pub const callMethod = types.callMethod;
pub const CallNonVirtualMethodError = types.CallNonVirtualMethodError;
pub const callNonVirtualMethod = types.callNonVirtualMethod;
pub const GetStaticFieldIdError = types.GetStaticFieldIdError;
pub const getStaticFieldId = types.getStaticFieldId;
pub const getStaticField = types.getStaticField;
pub const setStaticField = types.setStaticField;
pub const GetStaticMethodIdError = types.GetStaticMethodIdError;
pub const getStaticMethodId = types.getStaticMethodId;
pub const CallStaticMethodError = types.CallStaticMethodError;
pub const callStaticMethod = types.callStaticMethod;
pub const NewStringError = types.NewStringError;
pub const newString = types.newString;
pub const getStringLength = types.getStringLength;
pub const GetStringCharsError = types.GetStringCharsError;
pub const GetStringCharsReturn = types.GetStringCharsReturn;
pub const getStringChars = types.getStringChars;
pub const releaseStringChars = types.releaseStringChars;
pub const NewStringUTFError = types.NewStringUTFError;
pub const newStringUTF = types.newStringUTF;
pub const getStringUTFLength = types.getStringUTFLength;
pub const GetStringUTFCharsError = types.GetStringUTFCharsError;
pub const GetStringUTFCharsReturn = types.GetStringUTFCharsReturn;
pub const getStringUTFChars = types.getStringUTFChars;
pub const releaseStringUTFChars = types.releaseStringUTFChars;
pub const GetStringRegionError = types.GetStringRegionError;
pub const getStringRegion = types.getStringRegion;
pub const GetStringUTFRegionError = types.GetStringUTFRegionError;
pub const getStringUTFRegion = types.getStringUTFRegion;
pub const GetStringCriticalError = types.GetStringCriticalError;
pub const GetStringCriticalReturn = types.GetStringCriticalReturn;
pub const getStringCritical = types.getStringCritical;
pub const releaseStringCritical = types.releaseStringCritical;
pub const getDirectBufferAddress = types.getDirectBufferAddress;
pub const NewDirectByteBufferError = types.NewDirectByteBufferError;
pub const newDirectByteBuffer = types.newDirectByteBuffer;
pub const getArrayLength = types.getArrayLength;
pub const NewObjectArrayError = types.NewObjectArrayError;
pub const newObjectArray = types.newObjectArray;
pub const GetObjectArrayElementError = types.GetObjectArrayElementError;
pub const getObjectArrayElement = types.getObjectArrayElement;
pub const SetObjectArrayElementError = types.SetObjectArrayElementError;
pub const setObjectArrayElement = types.setObjectArrayElement;
pub const NewPrimitiveArrayError = types.NewPrimitiveArrayError;
pub const newPrimitiveArray = types.newPrimitiveArray;
pub const GetPrimitiveArrayElementsError = types.GetPrimitiveArrayElementsError;
pub const GetPrimitiveArrayElementsReturn = types.GetPrimitiveArrayElementsReturn;
pub const getPrimitiveArrayElements = types.getPrimitiveArrayElements;
pub const ReleasePrimitiveArrayElementsMode = types.ReleasePrimitiveArrayElementsMode;
pub const releasePrimitiveArrayElements = types.releasePrimitiveArrayElements;
pub const GetPrimitiveArrayRegionError = types.GetPrimitiveArrayRegionError;
pub const getPrimitiveArrayRegion = types.getPrimitiveArrayRegion;
pub const SetPrimitiveArrayRegionError = types.SetPrimitiveArrayRegionError;
pub const setPrimitiveArrayRegion = types.setPrimitiveArrayRegion;
pub const GetPrimitiveArrayCriticalError = types.GetPrimitiveArrayCriticalError;
pub const GetPrimitiveArrayCriticalReturn = types.GetPrimitiveArrayCriticalReturn;
pub const getPrimitiveArrayCritical = types.getPrimitiveArrayCritical;
pub const releasePrimitiveArrayCritical = types.releasePrimitiveArrayCritical;
pub const JavaVMOption = types.JavaVMOption;
pub const JavaVMInitArgs = types.JavaVMInitArgs;
pub const JavaVM = types.JavaVM;
pub const getCreatedJavaVMs = types.getCreatedJavaVMs;
pub const getCreatedJavaVM = types.getCreatedJavaVM;
pub const CreateJavaVMReturn = types.CreateJavaVMReturn;
pub const createJavaVM = types.createJavaVM;
pub const destroyJavaVM = types.destroyJavaVM;
pub const attachCurrentThread = types.attachCurrentThread;
pub const attachCurrentThreadAsDaemon = types.attachCurrentThreadAsDaemon;
pub const detachCurrentThread = types.detachCurrentThread;
pub const getEnv = types.getEnv;
pub const action = types.action;

pub fn exportAs(comptime name: []const u8, function: *const anyopaque) void {
    var z: [name.len]u8 = undefined;
    for (name, 0..) |v, i| z[i] = switch (v) {
        '.' => '_',
        else => v,
    };

    @export(function, .{ .name = "Java_" ++ &z, .linkage = .strong });
}

pub fn exportUnder(comptime class_name: []const u8, functions: anytype) void {
    inline for (std.meta.fields(@TypeOf(functions))) |field| {
        const z = @field(functions, field.name);

        if (std.mem.eql(u8, field.name, "onLoad"))
            @export(z, .{ .name = "JNI_OnLoad", .linkage = .strong })
        else if (std.mem.eql(u8, field.name, "onUnload"))
            @export(z, .{ .name = "JNI_OnUnload", .linkage = .strong })
        else
            exportAs(class_name ++ "." ++ field.name, &z);
    }
}

fn printSourceAtAddressJava(allocator: std.mem.Allocator, debug_info: *std.debug.DebugInfo, writer: anytype, address: usize) !void {
    const module = debug_info.getModuleForAddress(address) catch |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => {
            return try writer.writeAll((" " ** 8) ++ "at unknown (missing/invalud debug info)");
        },
        else => return err,
    };

    const symbol_info = if (comptime is_zig_master)
        try module.getSymbolAtAddress(allocator, address)
    else
        try module.getSymbolAtAddress(address);

    defer if (comptime is_zig_master) symbol_info.deinit(allocator) else symbol_info.deinit();

    if (symbol_info.line_info) |li| {
        try writer.print((" " ** 8) ++ "at {s}({s}:{d}:{d})", .{ symbol_info.symbol_name, li.file_name, li.line, li.column });
    } else {
        try writer.print((" " ** 8) ++ "at {s}({s}:unknown)", .{ symbol_info.symbol_name, symbol_info.compile_unit_name });
    }
}

fn writeStackTraceJava(
    allocator: std.mem.Allocator,
    stack_trace: std.builtin.StackTrace,
    writer: anytype,
    debug_info: *std.debug.DebugInfo,
) !void {
    if (builtin.strip_debug_info) return error.MissingDebugInfo;

    var frame_index: usize = 0;
    var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

    while (frames_left != 0) : ({
        frames_left -= 1;
        frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
    }) {
        const return_address = stack_trace.instruction_addresses[frame_index];
        try printSourceAtAddressJava(allocator, debug_info, writer, return_address - 1);
        if (frames_left != 1) try writer.writeByte('\n');
    }
}

fn formatStackTraceJava(writer: anytype, trace: std.builtin.StackTrace) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const debug_info = std.debug.getSelfDebugInfo() catch return;
    try writer.writeAll("\n");
    writeStackTraceJava(arena.allocator(), trace, writer, debug_info) catch |err| {
        try writer.print("Unable to print stack trace: {s}\n", .{@errorName(err)});
    };
}

// --- Code ~~stolen~~ adapted from debug.zig ends here ---

fn splitError(comptime T: type) struct { error_set: ?type = null, payload: type } {
    return switch (@typeInfo(T)) {
        .error_union => |u| .{ .error_set = u.error_set, .payload = u.payload },
        else => .{ .payload = T },
    };
}

/// NOTE: This is sadly required as @Type for Fn is not implemented so we cannot autowrap functions
pub fn wrapErrors(function: anytype, args: anytype) splitError(@typeInfo(@TypeOf(function)).@"fn".return_type.?).payload {
    const se = splitError(@typeInfo(@TypeOf(function)).@"fn".return_type.?);
    var env: *types.JNIEnv = undefined;

    switch (@TypeOf(args[0])) {
        *types.JNIEnv => env = args[0],
        *types.JavaVM => env = args[0].getEnv(types.JNIVersion{ .major = 10, .minor = 0 }) catch unreachable,
        else => unreachable,
    }

    if (se.error_set) |_| {
        return @call(.auto, function, args) catch |err| {
            const maybe_ert = @errorReturnTrace();
            if (maybe_ert) |ert| {
                var err_buf = std.ArrayList(u8).init(std.heap.page_allocator);
                defer err_buf.deinit();

                err_buf.writer().writeAll(@errorName(err)) catch unreachable;
                formatStackTraceJava(err_buf.writer(), ert.*) catch unreachable;
                err_buf.writer().writeByte(0) catch unreachable;

                env.throwGeneric(@as([*c]const u8, @ptrCast(err_buf.items))) catch unreachable;
            } else {
                var buf: [512]u8 = undefined;
                const msg = std.fmt.bufPrintZ(&buf, "{s}", .{@errorName(err)}) catch unreachable;
                env.throwGeneric(msg) catch unreachable;
            }

            // Even though an exception technically kills execution we
            // must still return something; just return undefined
            return undefined;
        };
    } else {
        return @call(.auto, function, args);
    }
}

test {
    std.testing.refAllDecls(@This());
}
