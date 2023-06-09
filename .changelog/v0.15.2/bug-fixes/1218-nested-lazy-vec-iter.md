- Fixed an issue with the iterator of LazyMap with a nested LazyVec collection
  that would match non-data keys and fail to decode those with the data decoder.
  ([#1218](https://github.com/anoma/namada/pull/1218))
