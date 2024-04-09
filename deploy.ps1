gsudo {
	sc.exe stop kresd

	$msys_local_dir = "c:\msys64\usr\local\"
	$msys_local_bin = Join-Path $msys_local_dir -ChildPath "bin"
	$msys_local_lib = Join-Path $msys_local_dir -ChildPath "lib"
	$msys_local_knot_resolver = Join-Path $msys_local_lib -ChildPath "knot-resolver"
	$msys_local_lua = Join-Path $msys_local_lib -ChildPath "lua"
	$msys_local_pkgconfig = Join-Path $msys_local_lib -ChildPath "pkgconfig"
	$msys_local_sbin = Join-Path $msys_local_dir -ChildPath "sbin"

	$msys_services_local_dir = "c:\bin\msys64_services\usr\local\"
	$msys_services_local_bin = Join-Path $msys_services_local_dir -ChildPath "bin"
	$msys_services_local_lib = Join-Path $msys_services_local_dir -ChildPath "lib"
	$msys_services_local_knot_resolver = Join-Path $msys_services_local_lib -ChildPath "knot-resolver"
	$msys_services_local_lua = Join-Path $msys_services_local_lib -ChildPath "lua"
	$msys_services_local_pkgconfig = Join-Path $msys_services_local_lib -ChildPath "pkgconfig"
	$msys_services_local_sbin = Join-Path $msys_services_local_dir -ChildPath "sbin"

	robocopy "$msys_local_bin" "$msys_services_local_bin" "kdig.exe" "khost.exe" "knsec3hash.exe" "knsupdate.exe" "lmdb.dll" "lua51.dll" "msys-dnssec-*.dll" "msys-knot-*.dll" "msys-kres-*.dll" "msys-zscanner-*.dll" /w:5 /xo
	robocopy "$msys_local_lib" "$msys_services_local_lib" "libdnssec.*" "libknot.*" "libkres.*" "libluajit-5.1.*" "libzscanner.*" /w:5 /xo
	robocopy "$msys_local_knot_resolver" "$msys_services_local_knot_resolver" /w:5 /xo /s
	robocopy "$msys_local_lua" "$msys_services_local_lua" /w:5 /xo /s
	robocopy "$msys_local_pkgconfig" "$msys_services_local_pkgconfig" "libdnssec.pc" "libknot.pc" "libkres.pc" "libzcanner.pc" "lmdb.pc" "luajit.pc" /w:5 /xo
	robocopy "$msys_local_sbin" "$msys_services_local_sbin" "kresc.exe" "kres-cache-gc.exe" "kresd.exe" "libkresd.exe.a" /w:5 /xo

	# luajit's name changes on every rolling release...copy the latest to 'luajit.exe' in services

	# find last luajit-2.1.xyz.exe in local
	$latest_lua_jit = gci "$msys_local_bin" -Filter 'luajit-2.1.*.exe' `
			| sort LastWriteTime | select -Last 1 -ExpandProperty Name

	if (!$latest_lua_jit) {
		throw "Latest `"luajit-2.1.*.exe`" not found in $msys_local_bin"
	}


    $msys_luajit = Join-Path $msys_local_bin -ChildPath $latest_lua_jit
    $msys_services_luajit = Join-Path $msys_services_local_bin -ChildPath "luajit.exe"

    if (Test-Path $msys_services_luajit) {
		fc.exe /b $msys_luajit $msys_services_luajit > $null
		$copy_luajit = !$?
    } else {
		$copy_luajit = $true
    }

	if ($copy_luajit) {
		xcopy.exe $msys_luajit $msys_services_luajit /-i /y /f
	}

	sc.exe start kresd
}
