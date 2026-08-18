// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Clears the benign subset of Ghidra's {@code "inconsistent instruction
 * prototype"} bookmarks that the DP context work in #42 makes possible.
 *
 * <p>Background — {@code tms320c28x_addr.sinc} decodes an {@code @6bit}
 * operand through one of two constructors gated on {@code ctx_DP_valid}:
 * a resolved-address form ({@code @0xNNNNNN}) when DP is known, and a
 * runtime-expression fallback ({@code @0xNN}) otherwise. Different
 * constructors produce different p-code prototypes for the same byte
 * sequence. When two flows reach the same address with different
 * {@code ctx_DP_valid} values (e.g. one path through a MOVW DP writer,
 * another through a post-call invalidation), Ghidra commits one prototype
 * and flags the other with an {@code Error / Bad Instruction} bookmark
 * whose description contains {@code "inconsistent ... prototype"}.
 *
 * <p>Empirically on a larger F28377D image, 7 such bookmarks exist post-DP
 * (control run pre-DP: 0). 6 of the 7 sit at {@code ctx_DP_valid=0} at
 * bookmark time — the fallback constructor won on the persistent listing,
 * so the rendered operand is the raw offset and is not wrong. The cross-
 * flow disagreement is on a phantom alternative Ghidra considered but
 * didn't commit. Those bookmarks are pure noise and safe to clear.
 * The 1 remaining bookmark sits at {@code ctx_DP_valid=1}: the resolved
 * constructor won on the persistent listing, but at least one incoming
 * path had no valid DP, so the resolved address may not be justified on
 * that path. Those warrant human review and are left in place.
 *
 * <p>The permanent fix — collapsing to a single {@code @6bit} constructor
 * so no prototype conflict can arise — is tracked separately against
 * #42's design. This analyzer is a mitigation, not a substitute.
 */
public class TMS320C28xDpBookmarkCleanupAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x DP Bookmark Cleanup";
	private static final String DESCRIPTION =
		"Clears the benign 'inconsistent instruction prototype' bookmarks introduced by " +
		"the DP context work when the SLA's fallback @6bit constructor won on the " +
		"persistent listing (ctx_DP_valid=0). Bookmarks where the resolved form won " +
		"(ctx_DP_valid=1) are left in place for human review.";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String CTX_DP_VALID_NAME = "ctx_DP_valid";
	private static final String BAD_INSTRUCTION_CATEGORY = "Bad Instruction";
	// Ghidra's bookmark comment for this class of error contains both tokens; matching
	// both is more robust than pinning the exact phrase (which has varied across
	// Ghidra versions -- "Multiple flows produced inconsistent instruction prototype"
	// on 12.x, subtly different in earlier releases).
	private static final String INCONSISTENT_MARKER = "inconsistent";
	private static final String PROTOTYPE_MARKER = "prototype";

	public TMS320C28xDpBookmarkCleanupAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after the DP propagation analyzer's re-disassembly rounds have settled;
		// chaining after() twice keeps us behind FUNCTION_ANALYSIS.after() (where DP
		// propagation lives) without needing an explicit dependency edge.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) {
			return false;
		}
		return program.getProgramContext().getRegister(CTX_DP_VALID_NAME) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		ProgramContext context = program.getProgramContext();
		Register ctxDpValid = context.getRegister(CTX_DP_VALID_NAME);
		if (ctxDpValid == null) {
			return false;
		}

		BookmarkManager bm = program.getBookmarkManager();
		// Program-wide scan rather than restricting to `set`: bookmarks are sparse
		// (7 on a ~150k-instruction image in the audit) so the whole-program scan
		// cost is trivial, and a re-disassembly in an unrelated area can turn a
		// previously-consistent site into a conflicting one on any round. Cheaper
		// to sweep the whole set than to reason about which bookmarks are "in scope".
		List<Bookmark> toClear = new ArrayList<>();
		int reviewedRemaining = 0;
		Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Bookmark bkm = it.next();
			if (!BAD_INSTRUCTION_CATEGORY.equals(bkm.getCategory())) {
				continue;
			}
			String comment = bkm.getComment();
			if (comment == null) {
				continue;
			}
			String lower = comment.toLowerCase();
			if (!lower.contains(INCONSISTENT_MARKER) || !lower.contains(PROTOTYPE_MARKER)) {
				continue;
			}

			BigInteger valid = context.getValue(ctxDpValid, bkm.getAddress(), false);
			// valid == 0: fallback constructor won on the persistent listing; the
			// rendered @0xNN operand is not wrong; the cross-flow disagreement is on
			// a phantom the disassembler didn't commit. Safe to clear.
			// valid == 1 or null: resolved constructor won (or context is missing);
			// the resolved address may not be justified on all incoming paths.
			// Human review required -- leave the bookmark in place.
			if (valid != null && BigInteger.ZERO.equals(valid)) {
				toClear.add(bkm);
			}
			else {
				reviewedRemaining++;
			}
		}

		for (Bookmark bkm : toClear) {
			bm.removeBookmark(bkm);
		}
		if (!toClear.isEmpty() || reviewedRemaining > 0) {
			Msg.info(this, "cleared " + toClear.size() + " benign 'inconsistent " +
				"prototype' bookmark(s); " + reviewedRemaining + " left for review " +
				"(resolved constructor won on the persistent listing but at least " +
				"one incoming path has ctx_DP_valid != 1)");
		}
		return true;
	}
}
