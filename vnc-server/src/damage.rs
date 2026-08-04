//! Framebuffer damage tracking for incremental updates.

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

impl DamageTracker {
    pub fn new(width: u32, height: u32, stride: usize) -> Self {
        let tile_size = 64u32;
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
                let tile_x = tx * self.tile_size;
                let tile_y = ty * self.tile_size;
                let tile_w = self.tile_size.min(self.width - tile_x);
                let tile_h = self.tile_size.min(self.height - tile_y);

                let changed = self.tile_changed(frame, tile_x, tile_y, tile_w, tile_h);
                self.dirty_tiles[tile_idx] = changed;
            }
        }

        // Merge adjacent dirty tiles into rectangles
        let rects = self.merge_dirty_tiles();

        // Save frame for next comparison
        self.prev_frame.copy_from_slice(frame);

        rects
    }

    fn tile_changed(&self, frame: &[u8], tx: u32, ty: u32, tw: u32, th: u32) -> bool {
        for y in 0..th {
            let row = ty + y;
            let off = row as usize * self.stride + tx as usize * 4;
            let len = tw as usize * 4;
            if frame[off..off + len] != self.prev_frame[off..off + len] {
                return true;
            }
        }
        false
    }

    fn merge_dirty_tiles(&self) -> Vec<DamageRect> {
        let mut rects = Vec::new();
        let mut visited = vec![false; self.dirty_tiles.len()];

        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let idx = (ty * self.tiles_x + tx) as usize;
                if visited[idx] || !self.dirty_tiles[idx] {
                    continue;
                }

                // Find the extent of this dirty region
                let mut max_tx = tx;
                let mut max_ty = ty;

                // Expand right
                while max_tx + 1 < self.tiles_x {
                    let next_idx = (ty * self.tiles_x + max_tx + 1) as usize;
                    if self.dirty_tiles[next_idx] {
                        max_tx += 1;
                    } else {
                        break;
                    }
                }

                // Expand down
                'expand_down: while max_ty + 1 < self.tiles_y {
                    for x in tx..=max_tx {
                        let check_idx = ((max_ty + 1) * self.tiles_x + x) as usize;
                        if !self.dirty_tiles[check_idx] {
                            break 'expand_down;
                        }
                    }
                    max_ty += 1;
                }

                // Mark all tiles in this rectangle as visited
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

    /// Force the entire framebuffer as damaged (e.g. on full update request).
    pub fn force_full_damage(&self) -> Vec<DamageRect> {
        vec![DamageRect {
            x: 0,
            y: 0,
            width: self.width as u16,
            height: self.height as u16,
        }]
    }
}
