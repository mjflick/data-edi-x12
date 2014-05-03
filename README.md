data-edi-x12
============

Data::EDI::X12 was developed for Bizowie [ERP Software](http://bizowie.com/).  It allows for abstraction of the X12 standard for Perl.

synopsis
---------
        use Data::EDI::X12;

        my $x12 = Data::EDI::X12->new({ spec_file => 'edi.yaml', new_lines => 1, truncate_null => 1 });
        my $data = $x12->read_record(...);
        print $x12->write_record($data);

contribute
-----------

Please feel free to fork this repository and patch it.

