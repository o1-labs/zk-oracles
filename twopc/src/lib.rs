pub mod grable;
pub mod ot;
pub mod twopc_prot;

pub use grable::*;
pub use ot::*;
pub use twopc_prot::*;

use crypto_core::{AbstractChannel, Block};
use std::io::Result;

pub fn send_gc<C: AbstractChannel>(channel: &mut C, gc: &GarbledCircuit) -> Result<()> {
    for [x, y] in gc.gc_table.table.iter() {
        channel.write_block(x).unwrap();
        channel.write_block(y).unwrap();
    }

    channel.write_block(&gc.gc_table.public_one_label).unwrap();

    send_wirelabels(channel, &gc.output_zero_labels).unwrap();

    Ok(())
}

pub fn send_wirelabels<C: AbstractChannel>(channel: &mut C, wls: &Vec<WireLabel>) -> Result<()> {
    for i in 0..wls.len() {
        channel.write_bytes(&wls[i].id.to_le_bytes()).unwrap();
        channel.write_block(&wls[i].label).unwrap();
    }
    Ok(())
}

pub fn receive_gc<C: AbstractChannel>(channel: &mut C, gc: &mut GarbledCircuit) -> Result<()> {
    let mut table = vec![[Block::default(), Block::default()]; gc.gc_table.table.len()];

    for [x, y] in table.iter_mut() {
        *x = channel.read_block().unwrap();
        *y = channel.read_block().unwrap();
    }

    let public_one_label = channel.read_block().unwrap();
    let gc_table = GarbledCircuitTable::new(table, public_one_label);

    gc.gc_table = gc_table;

    receive_wirelabels(channel, &mut gc.output_zero_labels).unwrap();
    Ok(())
}

pub fn receive_wirelabels<C: AbstractChannel>(
    channel: &mut C,
    wls: &mut Vec<WireLabel>,
) -> Result<()> {
    let mut res = Vec::<WireLabel>::new();

    for _ in 0..wls.len() {
        let mut tmp = [0u8; 8];
        channel.read_bytes(&mut tmp).unwrap();
        let id = usize::from_le_bytes(tmp);

        let label = channel.read_block().unwrap();
        res.push(WireLabel { id, label });
    }

    *wls = res;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crypto_core::{local_channel_pair, AbstractChannel, AesRng, Block};
    use rand::Rng;
    use std::thread;

    use crate::{
        receive_gc, receive_wirelabels, send_gc, send_wirelabels, GarbledCircuit,
        GarbledCircuitTable, WireLabel,
    };

    #[test]
    fn send_recv_wls_test() {
        let mut rng = AesRng::new();
        let size = 100;
        let wls = (0..size)
            .map(|x| {
                let label = rng.gen::<Block>();
                WireLabel { id: x, label }
            })
            .collect::<Vec<WireLabel>>();

        let wls1 = wls.clone();
        let mut wls2 = wls.clone();

        let (mut sender, mut receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            send_wirelabels(&mut sender, &wls1).unwrap();
            sender.flush().unwrap();
        });

        receive_wirelabels(&mut receiver, &mut wls2).unwrap();

        assert_eq!(wls, wls2);

        handle.join().unwrap();
    }

    #[test]
    fn send_recv_gc_test() {
        let mut rng = AesRng::new();
        let size = 100;
        let wls = (0..size)
            .map(|x| {
                let label = rng.gen::<Block>();
                WireLabel { id: x, label }
            })
            .collect::<Vec<WireLabel>>();

        let public_one_label = rng.gen::<Block>();
        let table = (0..size)
            .map(|_| {
                let x = rng.gen::<Block>();
                let y = rng.gen::<Block>();
                [x, y]
            })
            .collect::<Vec<[Block; 2]>>();
        let gc_table = GarbledCircuitTable::new(table, public_one_label);
        let gc = GarbledCircuit::new(gc_table, wls);

        let gc1 = gc.clone();
        let mut gc2 = gc.clone();

        let (mut sender, mut receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            send_gc(&mut sender, &gc1).unwrap();
            sender.flush().unwrap();
        });

        receive_gc(&mut receiver, &mut gc2).unwrap();
        assert_eq!(gc, gc2);

        handle.join().unwrap();
    }
}
