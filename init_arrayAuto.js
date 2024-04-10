
function get_addr(){
    var linker_sym = Module.enumerateSymbols("linker")
    // console.log("do_dlopen_addr => ", JSON.stringify(linker_sym))
    hook_constructors(linker_sym)
}
function hook_constructors(linker_sym){
    for(var i = 0; i < linker_sym.length; i++){
        var name = linker_sym[i].name
        if(name.indexOf("__dl_g_ld_debug_verbosity") >= 0){
            var addr__dl_g_ld_debug_verbosity = linker_sym[i].address
            // console.log("addr__dl_g_ld_debug_verbosity => ", addr__dl_g_ld_debug_verbosity)
            ptr(addr__dl_g_ld_debug_verbosity).writeInt(2)
        }
        if(name.indexOf("__dl_async_safe_format_log") >= 0 && name.indexOf("va_list") < 0){
            // console.log("__dl_async_safe_format_log", JSON.stringify(linker_sym[i]))
            var addr__dl_async_safe_format_log = linker_sym[i].address
        }
    }
    if(addr__dl_async_safe_format_log){
        Interceptor.attach(addr__dl_async_safe_format_log, {
            onEnter: function(args){
                this.log_level = args[0]
                this.tag = ptr(args[1]).readCString()
                this.fmt = ptr(args[2]).readCString()
                if(this.fmt.indexOf("c-tor") >= 0 && this.fmt.indexOf("Done") < 0){
                    this.function_type = ptr(args[3]).readCString()
                    this.so_path = ptr(args[5]).readCString()
                    var strs = new Array()
                    strs = this.so_path.split("/")
                    this.so_name = strs.pop()
                    this.func_offset = ptr(args[4]).sub(Module.findBaseAddress(this.so_name))
                    console.log("func_type: ", this.function_type,
                    "\nso_name: ", this.so_name,
                    "\nso_path: ", this.so_path,
                    "\nfunc_offset: ", this.func_offset.toString(16))
                }
            }, onLeave: function(retval){}
        })
    }
}

// void* do_dlopen(const char* name, 
//     int flags,
//     const android_dlextinfo* extinfo,
//     const void* caller_addr)

function hook_do_dlopen(_do_dlopen_addr){
    Interceptor.attach(_do_dlopen_addr, {
        onEnter: function (args) {
            console.log("so_name => ", args[0].readCString())
            console.log("flags => ", args[1])
            console.log("extinfo offset => ", (args[2] - args[2].Module.findBaseAddress("libdemoso1.so")).toString(16))
            console.log("caller_addr offset => ", (args[3] - args[3].Module.findBaseAddress("libdemoso1.so").toString(16)))
        }
    })
}

function hook_dlopen() {
    var dlopen = Module.findExportByName("linker64", "__loader_dlopen");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var so_name = args[0].readCString()
            console.log("so_name => ", so_name)
            if (so_name.indexOf("libdemoso1.so") >= 0) this.call_hook = true
        }
    });
}

function replace_pthread(){
    var pthread_create_addr = Module.findExportByName("libc.so", 'pthread_create')
    console.log("pthread_create_addr => ", pthread_create_addr)
    var pthread_create = new NativeFunction(pthread_create_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])
    Interceptor.replace(pthread_create_addr, new NativeCallback(function(args0, args1, args2, args3){
        console.log("replace_pthread args: ", args0, args1, args2, args3)
        var libdemoso1_addr = Module.findBaseAddress("libdemoso1.so")
        if(libdemoso1_addr != null){
            console.log("libdemoso1_addr => ", libdemoso1_addr)
            console.log("dete_frida_loop_offset is => ", args2 - libdemoso1_addr)
            return null
        }
        return pthread_create(args0, args1, args2, args3)
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']
    ))
}

setImmediate(get_addr)
