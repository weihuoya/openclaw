//! Framebuffer damage tracking for incremental updates.

use std::collections::HashMap;

/// Side length of a damage tile in pixels.
const TILE_SIZE: u32 = 64;

/// Tracks which regions of the framebuffer have changed.
pub struct DamageTracker {
    width: u32,
    height: u32,
    tile_size: u32,
    tiles_x: u32,
    tiles_y: u32,
    prev_frame: Vec<u8>,
    dirty_tiles: Vec<bool>,
    stride: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct DamageRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// A rectangle that can be copied from the previous frame.
#[derive(Debug, Clone, Copy)]
pub struct CopyRect {
    pub src_x: u16,
    pub src_y: u16,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Clone, Copy)]
enum TileState {
    Unchanged,
    Damaged,
    CopyRect { src_tx: u32, src_ty: u32 },
}

impl DamageTracker {
    pub fn new(width: u32, height: u32, stride: usize) -> Self {
        let tile_size = TILE_SIZE;
        let tiles_x = width.div_ceil(tile_size);
        let tiles_y = height.div_ceil(tile_size);
        let num_tiles = (tiles_x * tiles_y) as usize;
        let size = height as usize * stride;

        Self {
            width,
            height,
            tile_size,
            tiles_x,
            tiles_y,
            prev_frame: vec![0u8; size],
            dirty_tiles: vec![false; num_tiles],
            stride,
        }
    }

    /// Compare a new frame against the previous one and return changed rectangles.
    pub fn compute_damage(&mut self, frame: &[u8]) -> Vec<DamageRect> {
        assert_eq!(frame.len(), self.prev_frame.len());

        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let tile_idx = (ty * self.tiles_x + tx) as usize;
                self.dirty_tiles[tile_idx] = self.tile_changed(frame, tx, ty);
            }
        }

        // Mark all tiles as damaged for the simpler API.
        let mut all_damaged = vec![TileState::Damaged; self.dirty_tiles.len()];
        for (idx, changed) in self.dirty_tiles.iter().enumerate() {
            if !changed {
                all_damaged[idx] = TileState::Unchanged;
            }
        }
        let rects = self.merge_damage_tiles(&all_damaged);

        // Save frame for next comparison
        self.prev_frame.copy_from_slice(frame);

        rects
    }

    /// Compare a new frame against the previous one and return both rectangles
    /// that can be copied from the previous frame and rectangles that need new
    /// pixel data.
    ///
    /// This is useful for the CopyRect encoding: when content moves (e.g.
    /// scrolling or window movement), the client can be instructed to copy the
    /// pixels from their old location instead of receiving them again.
    pub fn compute_damage_with_copyrects(
        &mut self,
        frame: &[u8],
    ) -> (Vec<CopyRect>, Vec<DamageRect>) {
        assert_eq!(frame.len(), self.prev_frame.len());

        // Build a hash map from previous-frame tile hashes to tile positions.
        // Collisions are resolved by exact comparison later.
        let mut prev_hashes: HashMap<u64, Vec<(u32, u32)>> = HashMap::new();
        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let hash = self.tile_hash(&self.prev_frame, tx, ty);
                prev_hashes.entry(hash).or_default().push((tx, ty));
            }
        }

        let mut states = vec![TileState::Unchanged; (self.tiles_x * self.tiles_y) as usize];

        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let idx = (ty * self.tiles_x + tx) as usize;
                if !self.tile_changed(frame, tx, ty) {
                    continue;
                }

                let hash = self.tile_hash(frame, tx, ty);
                let mut matched = None;
                if let Some(candidates) = prev_hashes.get(&hash) {
                    for &(src_tx, src_ty) in candidates {
                        if self.tiles_equal(frame, &self.prev_frame, tx, ty, src_tx, src_ty) {
                            matched = Some((src_tx, src_ty));
                            break;
                        }
                    }
                }

                states[idx] = match matched {
                    Some((src_tx, src_ty)) => TileState::CopyRect { src_tx, src_ty },
                    None => TileState::Damaged,
                };
            }
        }

        let copy_rects = self.merge_copyrect_tiles(&states);
        let damage_rects = self.merge_damage_tiles(&states);

        // Save frame for next comparison
        self.prev_frame.copy_from_slice(frame);

        (copy_rects, damage_rects)
    }

    fn tile_bounds(&self, tx: u32, ty: u32) -> (u32, u32, u32, u32) {
        let x = tx * self.tile_size;
        let y = ty * self.tile_size;
        let w = self.tile_size.min(self.width - x);
        let h = self.tile_size.min(self.height - y);
        (x, y, w, h)
    }

    fn tile_changed(&self, frame: &[u8], tx: u32, ty: u32) -> bool {
        let (x, y, w, h) = self.tile_bounds(tx, ty);
        for row in 0..h {
            let row_y = y + row;
            let off = row_y as usize * self.stride + x as usize * 4;
            let len = w as usize * 4;
            if frame[off..off + len] != self.prev_frame[off..off + len] {
                return true;
            }
        }
        false
    }

    fn tiles_equal(
        &self,
        frame_a: &[u8],
        frame_b: &[u8],
        tx_a: u32,
        ty_a: u32,
        tx_b: u32,
        ty_b: u32,
    ) -> bool {
        let (x_a, y_a, w, h) = self.tile_bounds(tx_a, ty_a);
        let (x_b, y_b, _, _) = self.tile_bounds(tx_b, ty_b);
        for row in 0..h {
            let off_a = (y_a + row) as usize * self.stride + x_a as usize * 4;
            let off_b = (y_b + row) as usize * self.stride + x_b as usize * 4;
            let len = w as usize * 4;
            if frame_a[off_a..off_a + len] != frame_b[off_b..off_b + len] {
                return false;
            }
        }
        true
    }

    fn tile_hash(&self, frame: &[u8], tx: u32, ty: u32) -> u64 {
        let (x, y, w, h) = self.tile_bounds(tx, ty);
        let mut hash = 0xcbf29ce484222325u64; // FNV-64 offset basis
        for row in 0..h {
            let row_y = y + row;
            let off = row_y as usize * self.stride + x as usize * 4;
            let len = w as usize * 4;
            for byte in &frame[off..off + len] {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3); // FNV-64 prime
            }
        }
        hash
    }

    fn merge_copyrect_tiles(&self, states: &[TileState]) -> Vec<CopyRect> {
        let mut rects = Vec::new();
        let mut visited = vec![false; states.len()];

        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let idx = (ty * self.tiles_x + tx) as usize;
                if visited[idx] {
                    continue;
                }
                let (src_tx, src_ty) = match states[idx] {
                    TileState::CopyRect { src_tx, src_ty } => (src_tx, src_ty),
                    _ => continue,
                };

                let src_offset_x = src_tx as i64 - tx as i64;
                let src_offset_y = src_ty as i64 - ty as i64;

                let mut max_tx = tx;
                let mut max_ty = ty;

                // Expand right: same source offset required.
                while max_tx + 1 < self.tiles_x {
                    let next_idx = (ty * self.tiles_x + max_tx + 1) as usize;
                    let expected_src_tx = (max_tx + 1) as i64 + src_offset_x;
                    let expected_src_ty = ty as i64 + src_offset_y;
                    match states[next_idx] {
                        TileState::CopyRect {
                            src_tx: stx,
                            src_ty: sty,
                        } if stx as i64 == expected_src_tx && sty as i64 == expected_src_ty => {
                            max_tx += 1;
                        }
                        _ => break,
                    }
                }

                // Expand down: all tiles in the row must have the same source offset.
                'expand_down: while max_ty + 1 < self.tiles_y {
                    for x in tx..=max_tx {
                        let check_idx = ((max_ty + 1) * self.tiles_x + x) as usize;
                        let expected_src_tx = x as i64 + src_offset_x;
                        let expected_src_ty = (max_ty + 1) as i64 + src_offset_y;
                        match states[check_idx] {
                            TileState::CopyRect {
                                src_tx: stx,
                                src_ty: sty,
                            } if stx as i64 == expected_src_tx && sty as i64 == expected_src_ty => {
                            }
                            _ => break 'expand_down,
                        }
                    }
                    max_ty += 1;
                }

                for y in ty..=max_ty {
                    for x in tx..=max_tx {
                        let vidx = (y * self.tiles_x + x) as usize;
                        visited[vidx] = true;
                    }
                }

                let x = tx * self.tile_size;
                let y = ty * self.tile_size;
                let w = ((max_tx - tx + 1) * self.tile_size).min(self.width - x);
                let h = ((max_ty - ty + 1) * self.tile_size).min(self.height - y);

                let src_x = ((tx as i64 + src_offset_x) * self.tile_size as i64) as u16;
                let src_y = ((ty as i64 + src_offset_y) * self.tile_size as i64) as u16;

                rects.push(CopyRect {
                    src_x,
                    src_y,
                    x: x as u16,
                    y: y as u16,
                    width: w as u16,
                    height: h as u16,
                });
            }
        }

        rects
    }

    fn merge_damage_tiles(&self, states: &[TileState]) -> Vec<DamageRect> {
        let dirty: Vec<bool> = states
            .iter()
            .map(|s| matches!(s, TileState::Damaged))
            .collect();
        merge_dirty_tiles(
            &dirty,
            self.tiles_x,
            self.tiles_y,
            self.tile_size,
            self.width,
            self.height,
        )
    }
}

/// Merge a tile bitmap into a minimal set of rectangles using greedy
/// right-then-down expansion.
fn merge_dirty_tiles(
    dirty: &[bool],
    tiles_x: u32,
    tiles_y: u32,
    tile_size: u32,
    width: u32,
    height: u32,
) -> Vec<DamageRect> {
    let mut rects = Vec::new();
    let mut visited = vec![false; dirty.len()];

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let idx = (ty * tiles_x + tx) as usize;
            if visited[idx] || !dirty[idx] {
                continue;
            }

            let mut max_tx = tx;
            let mut max_ty = ty;

            // Expand right
            while max_tx + 1 < tiles_x {
                let next_idx = (ty * tiles_x + max_tx + 1) as usize;
                if dirty[next_idx] {
                    max_tx += 1;
                } else {
                    break;
                }
            }

            // Expand down
            'expand_down: while max_ty + 1 < tiles_y {
                for x in tx..=max_tx {
                    let check_idx = ((max_ty + 1) * tiles_x + x) as usize;
                    if !dirty[check_idx] {
                        break 'expand_down;
                    }
                }
                max_ty += 1;
            }

            for y in ty..=max_ty {
                for x in tx..=max_tx {
                    let vidx = (y * tiles_x + x) as usize;
                    visited[vidx] = true;
                }
            }

            let x = tx * tile_size;
            let y = ty * tile_size;
            let w = ((max_tx - tx + 1) * tile_size).min(width - x);
            let h = ((max_ty - ty + 1) * tile_size).min(height - y);

            rects.push(DamageRect {
                x: x as u16,
                y: y as u16,
                width: w as u16,
                height: h as u16,
            });
        }
    }

    rects
}

/// Per-client damage accumulator backed by a tile bitmap.
///
/// Each connected client owns one of these. Whenever the global
/// [`DamageTracker`] detects changes between two captures, the changed regions
/// are added to every client's accumulator; when an update is actually sent to
/// a client, the accumulator is cleared. Because the state is a fixed-size
/// tile bitmap (`tiles_x * tiles_y` bits' worth of flags), accumulation is
/// naturally bounded no matter how many changes or requests arrive.
pub struct ClientDamage {
    width: u32,
    height: u32,
    tiles_x: u32,
    tiles_y: u32,
    tiles: Vec<bool>,
}

impl ClientDamage {
    /// Create an accumulator with the whole framebuffer marked damaged.
    ///
    /// This is the correct initial state for a new (or resized) client: its
    /// first update must contain the full screen.
    pub fn new(width: u32, height: u32) -> Self {
        Self::with_state(width, height, true)
    }

    /// Create an accumulator with no damage.
    pub fn empty(width: u32, height: u32) -> Self {
        Self::with_state(width, height, false)
    }

    fn with_state(width: u32, height: u32, damaged: bool) -> Self {
        let tiles_x = width.div_ceil(TILE_SIZE);
        let tiles_y = height.div_ceil(TILE_SIZE);
        Self {
            width,
            height,
            tiles_x,
            tiles_y,
            tiles: vec![damaged; (tiles_x * tiles_y) as usize],
        }
    }

    /// Whether any region is marked damaged.
    pub fn is_empty(&self) -> bool {
        !self.tiles.iter().any(|&t| t)
    }

    /// Mark the whole framebuffer as damaged.
    pub fn mark_full(&mut self) {
        self.tiles.fill(true);
    }

    /// Mark the tiles overlapping the given rectangle as damaged.
    ///
    /// Coordinates are clipped to the framebuffer bounds.
    pub fn add_rect(&mut self, x: u16, y: u16, w: u16, h: u16) {
        if w == 0 || h == 0 {
            return;
        }
        let x0 = (x as u32).min(self.width);
        let y0 = (y as u32).min(self.height);
        let x1 = (x as u32 + w as u32).min(self.width);
        let y1 = (y as u32 + h as u32).min(self.height);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let tx0 = x0 / TILE_SIZE;
        let tx1 = (x1 - 1) / TILE_SIZE;
        let ty0 = y0 / TILE_SIZE;
        let ty1 = (y1 - 1) / TILE_SIZE;
        for ty in ty0..=ty1 {
            for tx in tx0..=tx1 {
                self.tiles[(ty * self.tiles_x + tx) as usize] = true;
            }
        }
    }

    /// Mark all tiles overlapping the given damage rectangles.
    pub fn add_damage_rects(&mut self, rects: &[DamageRect]) {
        for r in rects {
            self.add_rect(r.x, r.y, r.width, r.height);
        }
    }

    /// Mark the destination regions of the given copy rectangles as damaged.
    pub fn add_copyrect_dsts(&mut self, rects: &[CopyRect]) {
        for r in rects {
            self.add_rect(r.x, r.y, r.width, r.height);
        }
    }

    /// Merge the marked tiles into rectangles without clearing them.
    pub fn rects(&self) -> Vec<DamageRect> {
        merge_dirty_tiles(
            &self.tiles,
            self.tiles_x,
            self.tiles_y,
            TILE_SIZE,
            self.width,
            self.height,
        )
    }

    /// Clear all damage (call after the accumulated regions have been sent).
    pub fn clear(&mut self) {
        self.tiles.fill(false);
    }

    /// Total number of tiles in the bitmap (the bound on accumulation).
    #[cfg(test)]
    fn tile_capacity(&self) -> usize {
        self.tiles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(width: u32, height: u32, fill: u8) -> Vec<u8> {
        vec![fill; (width * height * 4) as usize]
    }

    #[test]
    fn test_no_damage() {
        let mut tracker = DamageTracker::new(64, 64, 64 * 4);
        let frame = make_frame(64, 64, 0xff);
        tracker.prev_frame.copy_from_slice(&frame);
        let damage = tracker.compute_damage(&frame);
        assert!(damage.is_empty());
    }

    #[test]
    fn test_full_damage_first_frame() {
        let mut tracker = DamageTracker::new(64, 64, 64 * 4);
        let frame = make_frame(64, 64, 0xff);
        let damage = tracker.compute_damage(&frame);
        assert_eq!(damage.len(), 1);
        assert_eq!(damage[0].width, 64);
        assert_eq!(damage[0].height, 64);
    }

    #[test]
    fn test_copyrect_scroll_down() {
        let mut tracker = DamageTracker::new(128, 128, 128 * 4);
        let mut prev = make_frame(128, 128, 0x00);
        // Top-left blue, top-right green, bottom-left red, bottom-right yellow.
        for y in 0..64 {
            for x in 0..64 {
                let off = (y * 128 + x) * 4;
                prev[off] = 0xff; // blue
            }
            for x in 64..128 {
                let off = (y * 128 + x) * 4;
                prev[off + 1] = 0xff; // green
            }
        }
        for y in 64..128 {
            for x in 0..64 {
                let off = (y * 128 + x) * 4;
                prev[off + 2] = 0xff; // red
            }
            for x in 64..128 {
                let off = (y * 128 + x) * 4;
                prev[off] = 0xff;
                prev[off + 1] = 0xff; // yellow
            }
        }
        tracker.prev_frame.copy_from_slice(&prev);

        // Current frame: content shifted down by 64 pixels, top half becomes cyan.
        let mut current = make_frame(128, 128, 0x00);
        for y in 0..64 {
            for x in 0..128 {
                let off = (y * 128 + x) * 4;
                current[off] = 0xff;
                current[off + 2] = 0xff; // magenta, distinct from previous frame
            }
        }
        for y in 64..128 {
            for x in 0..128 {
                let src_off = ((y - 64) * 128 + x) * 4;
                let dst_off = (y * 128 + x) * 4;
                current[dst_off..dst_off + 4].copy_from_slice(&prev[src_off..src_off + 4]);
            }
        }

        let (copy_rects, damage) = tracker.compute_damage_with_copyrects(&current);
        assert!(!copy_rects.is_empty());
        assert!(!copy_rects.is_empty());
        // The bottom half should be detected as a copy from the top half.
        let bottom_copy = copy_rects.iter().any(|r| {
            r.x == 0
                && r.y == 64
                && r.src_x == 0
                && r.src_y == 0
                && r.width == 128
                && r.height == 64
        });
        assert!(
            bottom_copy,
            "expected bottom-half copy rect, got {:?}",
            copy_rects
        );
        // Top half should be damaged.
        assert!(damage
            .iter()
            .any(|r| r.x == 0 && r.y == 0 && r.width == 128 && r.height == 64));
    }

    #[test]
    fn test_client_damage_new_is_full() {
        let damage = ClientDamage::new(200, 100);
        assert!(!damage.is_empty());
        let rects = damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].x, 0);
        assert_eq!(rects[0].y, 0);
        assert_eq!(rects[0].width, 200);
        assert_eq!(rects[0].height, 100);
    }

    #[test]
    fn test_client_damage_empty_and_clear() {
        let mut damage = ClientDamage::empty(128, 128);
        assert!(damage.is_empty());
        assert!(damage.rects().is_empty());

        damage.add_rect(10, 10, 20, 20);
        assert!(!damage.is_empty());

        damage.clear();
        assert!(damage.is_empty());
        assert!(damage.rects().is_empty());
    }

    #[test]
    fn test_client_damage_add_rect_expands_to_tile_bounds() {
        let mut damage = ClientDamage::empty(256, 256);
        // A 1x1 rect inside tile (1, 0) marks the whole 64x64 tile.
        damage.add_rect(70, 5, 1, 1);
        let rects = damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].x, 64);
        assert_eq!(rects[0].y, 0);
        assert_eq!(rects[0].width, 64);
        assert_eq!(rects[0].height, 64);
    }

    #[test]
    fn test_client_damage_add_rect_clips_to_framebuffer() {
        let mut damage = ClientDamage::empty(100, 100);
        // Rect extends past the right/bottom edges; only the visible part counts.
        damage.add_rect(90, 90, 500, 500);
        let rects = damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].x, 64);
        assert_eq!(rects[0].y, 64);
        assert_eq!(rects[0].width, 36);
        assert_eq!(rects[0].height, 36);

        // Rects fully outside the framebuffer are ignored.
        damage.clear();
        damage.add_rect(200, 200, 10, 10);
        assert!(damage.is_empty());

        // Zero-sized rects are ignored.
        damage.add_rect(0, 0, 0, 10);
        damage.add_rect(0, 0, 10, 0);
        assert!(damage.is_empty());
    }

    #[test]
    fn test_client_damage_accumulates_across_frames() {
        // Simulates a client with no pending request: changes from two
        // consecutive frame diffs must both be present when it finally asks.
        let mut damage = ClientDamage::empty(256, 64);
        damage.add_damage_rects(&[DamageRect {
            x: 0,
            y: 0,
            width: 64,
            height: 64,
        }]);
        // Second frame diff arrives before any update was sent.
        damage.add_damage_rects(&[DamageRect {
            x: 192,
            y: 0,
            width: 64,
            height: 64,
        }]);

        let rects = damage.rects();
        assert_eq!(rects.len(), 2);
        assert!(rects
            .iter()
            .any(|r| r.x == 0 && r.width == 64 && r.height == 64));
        assert!(rects
            .iter()
            .any(|r| r.x == 192 && r.width == 64 && r.height == 64));

        // After the update is sent the accumulator is cleared.
        damage.clear();
        assert!(damage.is_empty());
    }

    #[test]
    fn test_client_damage_merges_adjacent_tiles() {
        let mut damage = ClientDamage::empty(256, 128);
        damage.add_rect(0, 0, 128, 64);
        damage.add_rect(0, 64, 64, 64);
        let rects = damage.rects();
        // Tiles (0,0),(1,0) merge horizontally; (0,1) stays separate because
        // the 2x1 row above cannot expand down past the missing tile (1,1).
        assert_eq!(rects.len(), 2);
        assert!(rects
            .iter()
            .any(|r| r.x == 0 && r.y == 0 && r.width == 128 && r.height == 64));
        assert!(rects
            .iter()
            .any(|r| r.x == 0 && r.y == 64 && r.width == 64 && r.height == 64));
    }

    #[test]
    fn test_client_damage_is_bounded() {
        // Flooding the accumulator with requests must never grow memory:
        // the state is a fixed tile bitmap.
        let mut damage = ClientDamage::new(1920, 1080);
        let capacity = damage.tile_capacity();
        assert_eq!(capacity, (30 * 17) as usize); // 1920/64 x 1080/64 tiles
        for i in 0..10_000u32 {
            let x = ((i * 37) % 1920) as u16;
            let y = ((i * 91) % 1080) as u16;
            damage.add_rect(x, y, 8, 8);
        }
        assert_eq!(damage.tile_capacity(), capacity);
        assert!(!damage.is_empty());
        // Merged output is bounded by the tile count as well.
        assert!(damage.rects().len() <= capacity);
    }

    #[test]
    fn test_client_damage_mark_full() {
        let mut damage = ClientDamage::empty(100, 100);
        damage.mark_full();
        let rects = damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].width, 100);
        assert_eq!(rects[0].height, 100);
    }

    #[test]
    fn test_client_damage_copyrect_dsts() {
        let mut damage = ClientDamage::empty(256, 128);
        damage.add_copyrect_dsts(&[CopyRect {
            src_x: 0,
            src_y: 0,
            x: 0,
            y: 64,
            width: 64,
            height: 64,
        }]);
        let rects = damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].x, 0);
        assert_eq!(rects[0].y, 64);
    }
}
