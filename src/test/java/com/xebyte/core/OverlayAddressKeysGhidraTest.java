package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Two functions at one offset, in the default space and an overlay, have two spellings. Bare
 * hex gave them one, so anything keyed by address (a get_functions result, a resource URI)
 * could not tell them apart.
 */
public class OverlayAddressKeysGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Function base;
    private Function overlay;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("overlay", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        MemoryBlock ovl = builder.createOverlayMemory("OVL", "0x1000", 0x100);
        Address ovlEntry = ovl.getStart();
        // MOV EAX,1; RET   and   MOV EAX,2; RET
        builder.setBytes("0x1000", "b8 01 00 00 00 c3");
        builder.withTransaction(() -> {
            try {
                program.getMemory().setBytes(ovlEntry, new byte[] {(byte) 0xb8, 2, 0, 0, 0, (byte) 0xc3});
            } catch (Exception e) {
                throw new AssertionError(e);
            }
            new DisassembleCommand(builder.addr("0x1000"), new AddressSet(builder.addr("0x1000"),
                builder.addr("0x1005")), true).applyTo(program, TaskMonitor.DUMMY);
            new DisassembleCommand(ovlEntry, new AddressSet(ovlEntry, ovlEntry.add(5)), true)
                .applyTo(program, TaskMonitor.DUMMY);
            try {
                program.getFunctionManager().createFunction("in_overlay", ovlEntry,
                    new AddressSet(ovlEntry, ovlEntry.add(5)), ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        base = builder.createFunction("0x1000");
        overlay = program.getFunctionManager().getFunctionAt(ovlEntry);
        assertNotNull(overlay);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void theDefaultSpaceStaysBareAndTheOverlayIsQualified() {
        assertEquals("00001000", AddressKeys.of(base));
        assertEquals("an overlay key uses Ghidra's own '::' spelling",
            overlay.getEntryPoint().toString(), AddressKeys.of(overlay));
        assertEquals("OVL::00001000", AddressKeys.of(overlay));
        assertSame(base, AddressKeys.function(program, "00001000"));
        assertSame(overlay, AddressKeys.function(program, "OVL::00001000"));
        assertSame("the single-colon spelling still resolves",
            overlay, AddressKeys.function(program, "OVL:00001000"));
        assertEquals("a caller's spelling of the default space becomes the bare key",
            "00001000", AddressKeys.canonical(program, "0x1000"));
        assertEquals("either overlay spelling becomes the '::' key",
            "OVL::00001000", AddressKeys.canonical(program, "OVL:0x1000"));
    }

    @Test
    public void keyStringsKeepTheirSeparator() {
        assertEquals("OVL::00001000", AddressKeys.normalize("OVL::0x00001000"));
        assertEquals("ram:00001000", AddressKeys.normalize("ram:0X00001000"));
        assertEquals("00001000", AddressKeys.normalize("0x00001000"));
        assertEquals("OVL", AddressKeys.space("OVL::1000"));
        assertEquals("ram", AddressKeys.space("ram:1000"));
        assertEquals("", AddressKeys.space("1000"));
        assertEquals(0x1000L, AddressKeys.offset("OVL::1000"));
    }
}
